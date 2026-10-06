import { Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { WebhooksService } from './webhooks.service';

interface DomainEvent {
  tenantId: string;
  [key: string]: unknown;
}

/**
 * Decouples domain logic (AuthService, InvitationsService, ...) from the
 * webhooks feature: those services just emit plain events and never need
 * to know whether webhooks are configured/enabled at all.
 */
@Injectable()
export class WebhookEventsListener {
  constructor(private readonly webhooks: WebhooksService) {}

  @OnEvent('user.registered')
  async onUserRegistered(payload: DomainEvent) {
    await this.webhooks.dispatchEvent(payload.tenantId, 'user.registered', payload);
  }

  @OnEvent('user.login')
  async onUserLogin(payload: DomainEvent) {
    await this.webhooks.dispatchEvent(payload.tenantId, 'user.login', payload);
  }

  @OnEvent('user.banned')
  async onUserBanned(payload: DomainEvent) {
    await this.webhooks.dispatchEvent(payload.tenantId, 'user.banned', payload);
  }

  @OnEvent('invitation.created')
  async onInvitationCreated(payload: DomainEvent) {
    await this.webhooks.dispatchEvent(payload.tenantId, 'invitation.created', payload);
  }

  @OnEvent('invitation.accepted')
  async onInvitationAccepted(payload: DomainEvent) {
    await this.webhooks.dispatchEvent(payload.tenantId, 'invitation.accepted', payload);
  }
}
