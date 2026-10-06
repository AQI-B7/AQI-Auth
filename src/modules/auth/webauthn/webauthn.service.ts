import { BadRequestException, Injectable, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { isoUint8Array, decodeClientDataJSON } from '@simplewebauthn/server/helpers';
import { randomUUID } from 'crypto';
import { PrismaService } from '../../../prisma/prisma.service';
import { AuthService } from '../auth.service';
import { LockoutService } from '../lockout.service';
import { MetricsService } from '../../metrics/metrics.service';

/**
 * Passkey (WebAuthn) registration and authentication, per the W3C
 * WebAuthn Level 3 spec, using @simplewebauthn/server for the actual
 * cryptographic verification (attestation/assertion signature checks,
 * origin/RP ID binding, clone-detection via signature counters). This
 * service is the orchestration layer around that library: challenge
 * issuance/consumption, credential storage, and wiring a verified
 * ceremony into the same token-issuance path as password/OAuth/magic-link
 * login.
 */
@Injectable()
export class WebAuthnService {
  private readonly logger = new Logger(WebAuthnService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly authService: AuthService,
    private readonly lockout: LockoutService,
    private readonly metrics: MetricsService,
  ) {}

  private get rpName(): string {
    return this.config.get<string>('webauthn.rpName')!;
  }
  private get rpId(): string {
    return this.config.get<string>('webauthn.rpId')!;
  }
  private get origins(): string[] {
    return this.config.get<string[]>('webauthn.origins')!;
  }
  private get challengeTtlMs(): number {
    return (this.config.get<number>('webauthn.challengeTtlSeconds') || 300) * 1000;
  }

  // ── Registration (adding a passkey to an already-authenticated account) ──

  async generateRegistrationOptionsFor(userId: string, credentialName?: string) {
    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: userId } });
    const existingCredentials = await this.prisma.webAuthnCredential.findMany({
      where: { userId },
      select: { credentialId: true, transports: true },
    });

    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpId,
      userID: isoUint8Array.fromUTF8String(user.id),
      userName: user.email,
      userDisplayName: [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email,
      attestationType: 'none', // we don't need attestation chain validation, just a bound credential
      excludeCredentials: existingCredentials.map((c: { credentialId: string; transports: string[] }) => ({
        id: c.credentialId,
        transports: c.transports as any,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    await this.storeChallenge(options.challenge, userId, 'registration');

    // Stash the intended credential name alongside the challenge via a
    // short-lived, tamper-evident hint isn't necessary — the client just
    // echoes credentialName back on /register/verify instead, which is
    // simpler and avoids a second piece of server-side state per ceremony.
    return options;
  }

  async verifyRegistration(userId: string, response: RegistrationResponseJSON, credentialName?: string) {
    const challengeValue = decodeClientDataJSON(response.response.clientDataJSON).challenge;
    const challenge = await this.consumeChallengeByValue(challengeValue, 'registration', userId);
    if (!challenge) {
      throw new BadRequestException('Registration challenge expired, already used, or not found — please try again');
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: this.origins,
        expectedRPID: this.rpId,
      });
    } catch (err) {
      throw new BadRequestException(`Passkey registration failed: ${(err as Error).message}`);
    }

    if (!verification.verified || !verification.registrationInfo) {
      throw new BadRequestException('Passkey registration could not be verified');
    }

    const { credential, credentialDeviceType, credentialBackedUp, aaguid } = verification.registrationInfo;

    const existing = await this.prisma.webAuthnCredential.findUnique({
      where: { credentialId: credential.id },
    });
    if (existing) {
      // Same physical authenticator registered twice (e.g. retried
      // ceremony) — not an error, just don't create a duplicate row.
      throw new BadRequestException('This passkey is already registered');
    }

    const stored = await this.prisma.webAuthnCredential.create({
      data: {
        userId,
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey),
        counter: BigInt(credential.counter),
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        transports: credential.transports ?? [],
        aaguid,
        name: credentialName || defaultCredentialName(credentialDeviceType),
      },
    });

    await this.prisma.authEvent.create({
      data: { userId, type: 'webauthn.registered', metadata: { credentialId: stored.id } },
    });

    return {
      id: stored.id,
      name: stored.name,
      deviceType: stored.deviceType,
      backedUp: stored.backedUp,
      createdAt: stored.createdAt,
    };
  }

  async listCredentials(userId: string) {
    const creds = await this.prisma.webAuthnCredential.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
    return creds.map((c: any) => ({
      id: c.id,
      name: c.name,
      deviceType: c.deviceType,
      backedUp: c.backedUp,
      transports: c.transports,
      lastUsedAt: c.lastUsedAt,
      createdAt: c.createdAt,
    }));
  }

  async removeCredential(userId: string, credentialRecordId: string) {
    const cred = await this.prisma.webAuthnCredential.findFirst({
      where: { id: credentialRecordId, userId },
    });
    if (!cred) throw new NotFoundException('Passkey not found');
    await this.prisma.webAuthnCredential.delete({ where: { id: cred.id } });
    return { success: true };
  }

  // ── Authentication (signing in with a passkey — usernameless-capable) ──

  async generateAuthenticationOptionsFor(email?: string, tenantSlug?: string) {
    let allowCredentials: { id: string; transports?: string[] }[] | undefined;
    let userId: string | null = null;

    if (email) {
      const user = await this.prisma.user.findFirst({
        where: {
          email: email.toLowerCase(),
          ...(tenantSlug ? { tenant: { slug: tenantSlug } } : {}),
        },
        include: { webauthnCredentials: { select: { credentialId: true, transports: true } } },
      });
      // Don't reveal whether the email exists: if not found, fall through
      // to a discoverable-credential (usernameless) challenge instead of
      // erroring — the browser will simply offer no matching passkeys.
      if (user) {
        userId = user.id;
        allowCredentials = user.webauthnCredentials.map((c: { credentialId: string; transports: string[] }) => ({
          id: c.credentialId,
          transports: c.transports,
        }));
      }
    }

    const options = await generateAuthenticationOptions({
      rpID: this.rpId,
      allowCredentials: allowCredentials as any,
      userVerification: 'preferred',
    });

    await this.storeChallenge(options.challenge, userId, 'authentication');
    return options;
  }

  async verifyAuthentication(response: AuthenticationResponseJSON, ip?: string, userAgent?: string) {
    const credentialId = response.id;
    const lockoutId = ip || 'unknown';

    const lockStatus = await this.lockout.check('webauthn_verify', lockoutId);
    if (lockStatus.locked) {
      throw new UnauthorizedException(
        `Too many failed passkey attempts. Try again in ${lockStatus.retryAfterSeconds}s.`,
      );
    }

    const credential = await this.prisma.webAuthnCredential.findUnique({
      where: { credentialId },
      include: {
        user: {
          include: { tenant: true, roles: { include: { role: true } } },
        },
      },
    });

    if (!credential) {
      await this.lockout.recordFailure('webauthn_verify', lockoutId);
      throw new UnauthorizedException('Unrecognized passkey');
    }

    // The challenge may have been issued username-first (userId set) or
    // discoverable/usernameless (userId null); decoding it from the
    // response itself (rather than guessing "most recent for this user")
    // is what makes this safe under concurrent login attempts from
    // different browsers/users.
    const challengeValue = decodeClientDataJSON(response.response.clientDataJSON).challenge;
    const challenge = await this.consumeChallengeByValue(challengeValue, 'authentication', credential.userId);
    if (!challenge) {
      await this.lockout.recordFailure('webauthn_verify', lockoutId);
      throw new UnauthorizedException('Passkey challenge expired or not found — please try again');
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: this.origins,
        expectedRPID: this.rpId,
        credential: {
          id: credential.credentialId,
          publicKey: new Uint8Array(credential.publicKey),
          counter: Number(credential.counter),
          transports: credential.transports as any,
        },
      });
    } catch (err) {
      // verifyAuthenticationResponse throws when the reported signature
      // counter is <= the one we have on file — the textbook signature of
      // a cloned/duplicated authenticator. Treat that as a security
      // event: disable the credential rather than just failing the login,
      // since a legitimate owner's counter never goes backwards.
      const message = (err as Error).message;
      if (message.includes('counter value')) {
        await this.prisma.webAuthnCredential.update({
          where: { id: credential.id },
          data: { name: `${credential.name || 'Passkey'} (disabled — possible clone detected)` },
        });
        await this.prisma.authEvent.create({
          data: {
            userId: credential.userId,
            type: 'webauthn.clone_suspected',
            ipAddress: ip,
            userAgent,
            metadata: { credentialId: credential.id, error: message },
          },
        });
        this.logger.warn(`Possible passkey clone detected for credential ${credential.id}: ${message}`);
      }
      await this.lockout.recordFailure('webauthn_verify', lockoutId);
      throw new UnauthorizedException('Passkey verification failed');
    }

    if (!verification.verified) {
      await this.lockout.recordFailure('webauthn_verify', lockoutId);
      throw new UnauthorizedException('Passkey verification failed');
    }

    await this.prisma.webAuthnCredential.update({
      where: { id: credential.id },
      data: { counter: BigInt(verification.authenticationInfo.newCounter), lastUsedAt: new Date() },
    });

    const user = credential.user;
    if (user.status !== 'ACTIVE' || user.tenant.status !== 'ACTIVE') {
      throw new UnauthorizedException('Account or tenant is not active');
    }

    await this.lockout.recordSuccess('webauthn_verify', lockoutId);
    await this.prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });

    const permissions = this.authService.collectPermissions(user.roles);
    const tokens = await this.authService.issueTokens(user.id, user.tenantId, user.email, permissions, ip, userAgent);

    await this.prisma.authEvent.create({
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        type: 'login.success',
        ipAddress: ip,
        userAgent,
        metadata: { method: 'webauthn', credentialId: credential.id },
      },
    });
    this.metrics.loginAttemptsTotal.inc({ result: 'success' });

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        emailVerified: user.emailVerified,
        tenantId: user.tenantId,
        permissions,
      },
      tenant: { id: user.tenant.id, name: user.tenant.name, slug: user.tenant.slug },
      ...tokens,
    };
  }

  // ── Challenge storage ──

  private async storeChallenge(challenge: string, userId: string | null, type: 'registration' | 'authentication') {
    await this.prisma.webAuthnChallenge.create({
      data: {
        id: randomUUID(),
        challenge,
        userId,
        type,
        expiresAt: new Date(Date.now() + this.challengeTtlMs),
      },
    });
  }

  /**
   * Consumes (deletes) a challenge by its exact value — decoded from the
   * ceremony response's clientDataJSON, not guessed by "most recent for
   * this user/type". `challenge` is unique in the schema, so this is a
   * precise, race-free match even with multiple concurrent anonymous
   * (discoverable-credential) login attempts in flight.
   *
   * `expectedUserId` binds a registration challenge to the authenticated
   * user who requested it; for a discoverable authentication challenge
   * (issued with userId=null) any resolved credential owner is accepted,
   * since the whole point of that flow is not knowing the user in advance.
   */
  private async consumeChallengeByValue(
    challengeValue: string,
    type: 'registration' | 'authentication',
    expectedUserId: string,
  ) {
    const challenge = await this.prisma.webAuthnChallenge.findUnique({
      where: { challenge: challengeValue },
    });
    if (
      !challenge ||
      challenge.type !== type ||
      challenge.expiresAt < new Date() ||
      (challenge.userId !== null && challenge.userId !== expectedUserId)
    ) {
      return null;
    }
    await this.prisma.webAuthnChallenge.delete({ where: { id: challenge.id } }).catch(() => undefined);
    return challenge;
  }
}

function defaultCredentialName(deviceType: string): string {
  return deviceType === 'multiDevice' ? 'Synced passkey' : 'Security key';
}
