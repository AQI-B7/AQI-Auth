import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { renderBrandedEmail, BrandConfig } from './templates/branded-layout';
import { t } from './i18n/translations';

export interface SendEmailInput {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

/**
 * Thin, provider-agnostic mail sender with a shared branded layout and
 * basic i18n (see templates/branded-layout.ts and i18n/translations.ts).
 *
 * Optional by design: if SMTP_HOST is not configured the service falls
 * back to a JSON transport (dev/test) that never touches the network and
 * just logs what *would* have been sent — so the rest of the auth flows
 * (magic link, invitations, password reset, webhook alerts) keep working
 * without any mail provider configured. No dev-mode leakage once SMTP is
 * actually configured / NODE_ENV=production — see each caller.
 */
@Injectable()
export class EmailService implements OnModuleInit {
  private readonly logger = new Logger(EmailService.name);
  private transporter!: Transporter;
  private readonly from: string;
  private readonly brand: BrandConfig;
  private readonly defaultLocale: string;
  readonly enabled: boolean;

  constructor(private readonly config: ConfigService) {
    this.from = this.config.get<string>('email.from')!;
    this.enabled = this.config.get<boolean>('email.enabled') ?? false;
    this.brand = {
      productName: this.config.get<string>('branding.productName') || 'Auth Service',
      logoUrl: this.config.get<string>('branding.logoUrl'),
      primaryColor: this.config.get<string>('branding.primaryColor') || '#4f46e5',
      supportEmail: this.config.get<string>('branding.supportEmail'),
    };
    this.defaultLocale = this.config.get<string>('branding.defaultLocale') || 'en';
  }

  onModuleInit() {
    if (this.enabled) {
      this.transporter = nodemailer.createTransport({
        host: this.config.get<string>('email.host'),
        port: this.config.get<number>('email.port'),
        secure: this.config.get<boolean>('email.secure') ?? false,
        auth: this.config.get<string>('email.user')
          ? {
              user: this.config.get<string>('email.user'),
              pass: this.config.get<string>('email.pass'),
            }
          : undefined,
      });
      this.logger.log(
        `SMTP transport configured (${this.config.get<string>('email.host')}) — outgoing email enabled`,
      );
    } else {
      // jsonTransport never opens a socket; it just serializes the message.
      this.transporter = nodemailer.createTransport({ jsonTransport: true });
      this.logger.warn(
        'SMTP_HOST not set — email sending is running in local/dev mode (messages are logged, not delivered)',
      );
    }
  }

  async send(input: SendEmailInput): Promise<{ delivered: boolean; messageId?: string }> {
    try {
      const info = await this.transporter.sendMail({
        from: this.from,
        to: input.to,
        subject: input.subject,
        html: input.html,
        text: input.text ?? stripHtml(input.html),
      });

      if (!this.enabled) {
        this.logger.debug(`[dev email] to=${input.to} subject="${input.subject}"`);
        return { delivered: false, messageId: info.messageId };
      }
      return { delivered: true, messageId: info.messageId };
    } catch (err) {
      // Never let a mail-provider outage take down an auth request; the
      // caller (e.g. magic-link request) already returns a generic
      // success response to avoid account enumeration regardless.
      this.logger.error(`Failed to send email to ${input.to}: ${(err as Error).message}`);
      return { delivered: false };
    }
  }

  // ── Branded, localized transactional templates ─────────────

  async sendMagicLink(to: string, link: string, ttlMinutes: number, locale?: string) {
    const copy = t(locale, this.defaultLocale).magicLink;
    return this.send({
      to,
      subject: copy.subject,
      html: renderBrandedEmail(this.brand, {
        heading: copy.heading,
        bodyHtml: `<p>${copy.body(ttlMinutes)}</p>`,
        ctaLabel: copy.cta,
        ctaUrl: link,
        footerHtml: copy.footer,
        preheader: copy.subject,
      }),
    });
  }

  async sendPasswordReset(to: string, link: string, locale?: string) {
    const copy = t(locale, this.defaultLocale).passwordReset;
    return this.send({
      to,
      subject: copy.subject,
      html: renderBrandedEmail(this.brand, {
        heading: copy.heading,
        bodyHtml: `<p>${copy.body}</p>`,
        ctaLabel: copy.cta,
        ctaUrl: link,
        footerHtml: copy.footer,
        preheader: copy.subject,
      }),
    });
  }

  async sendInvitation(to: string, link: string, expiresOn: string, locale?: string) {
    const copy = t(locale, this.defaultLocale).invitation;
    return this.send({
      to,
      subject: copy.subject,
      html: renderBrandedEmail(this.brand, {
        heading: copy.heading,
        bodyHtml: `<p>${copy.body(expiresOn)}</p>`,
        ctaLabel: copy.cta,
        ctaUrl: link,
        preheader: copy.subject,
      }),
    });
  }

  async sendWebhookDeadLetterAlert(
    to: string,
    input: { endpointUrl: string; eventType: string; attempts: number; errorMessage?: string; deliveryId: string },
    locale?: string,
  ) {
    const copy = t(locale, this.defaultLocale).webhookDeadLetter;
    return this.send({
      to,
      subject: copy.subject(input.eventType),
      html: renderBrandedEmail(this.brand, {
        heading: copy.heading,
        bodyHtml: `
          <p>${copy.body(input.endpointUrl, input.eventType, input.attempts)}</p>
          <p><strong>${copy.lastError}:</strong> ${input.errorMessage || 'n/a'}</p>
          <p style="color:#9ca3af;font-size:12px;">Delivery ID: ${input.deliveryId}</p>`,
        footerHtml: copy.footer,
      }),
    });
  }
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}
