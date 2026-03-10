import crypto from 'node:crypto';

import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

const INTERCOM_API = 'https://api.intercom.io';
const API_VERSION = '2.11';

interface IntercomContact {
  id: string;
  external_id: string;
}

interface IntercomConversationPart {
  part_type: string;
  body: string;
  author: { type: string };
}

interface IntercomConversation {
  id: string;
  conversation_parts: {
    conversation_parts: IntercomConversationPart[];
  };
}

/**
 * Intercom adapter for testing Fin AI agents via the Conversations API.
 *
 * Requires an Intercom access token with conversation + contact permissions.
 * Creates a lead contact, opens conversations, and reads Fin's replies.
 */
export class IntercomAdapter extends BaseAdapter {
  private contactId: string | null = null;
  private conversationId: string | null = null;
  private readonly pollIntervalMs: number;
  private readonly maxPollAttempts: number;

  constructor(config: AdapterConfig) {
    if (!config.apiKey) {
      throw new Error('Intercom adapter requires an API access token (--api-key)');
    }

    super({
      ...config,
      baseUrl: INTERCOM_API,
      headers: {
        Authorization: `Bearer ${config.apiKey}`,
        'Intercom-Version': API_VERSION,
        Accept: 'application/json',
        ...config.headers,
      },
    });

    this.pollIntervalMs = config.intercomPollMs ?? 2000;
    this.maxPollAttempts = config.intercomMaxPollAttempts ?? 30;
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const message = lastUser?.content ?? '';

    await this.ensureContact();

    const start = performance.now();

    if (!this.conversationId) {
      // First message: create a new conversation
      const conv = await this.createConversation(message);
      this.conversationId = conv.id;
    } else {
      // Subsequent messages: reply to existing conversation
      await this.replyToConversation(message);
    }

    // Poll for Fin's response
    const content = await this.pollForReply();
    const latencyMs = Math.round(performance.now() - start);

    return { content, raw: { conversationId: this.conversationId, contactId: this.contactId }, latencyMs };
  }

  private async ensureContact(): Promise<void> {
    if (this.contactId) return;

    const externalId = `keelson-scanner-${crypto.randomUUID()}`;
    const { data } = await this.client.post<IntercomContact>('/contacts', {
      role: 'lead',
      name: 'Keelson Security Scanner',
      external_id: externalId,
    });

    this.contactId = data.id;
  }

  private async createConversation(body: string): Promise<{ id: string }> {
    const { data } = await this.client.post<{ id: string }>('/conversations', {
      from: { type: 'contact', id: this.contactId },
      body,
    });
    return data;
  }

  private async replyToConversation(body: string): Promise<void> {
    await this.client.post(`/conversations/${this.conversationId}/reply`, {
      message_type: 'comment',
      type: 'user',
      intercom_user_id: this.contactId,
      body,
    });
  }

  private async pollForReply(): Promise<string> {
    for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
      await new Promise((r) => setTimeout(r, this.pollIntervalMs));

      const { data } = await this.client.get<IntercomConversation>(
        `/conversations/${this.conversationId}`,
      );

      const parts = data.conversation_parts?.conversation_parts ?? [];

      // Find the latest bot/admin reply (Fin responds as bot or admin)
      const botReply = [...parts]
        .reverse()
        .find(
          (p) =>
            (p.author.type === 'bot' || p.author.type === 'admin') &&
            p.part_type === 'comment' &&
            p.body,
        );

      if (botReply) {
        // Strip HTML tags from Intercom's response
        return botReply.body.replace(/<[^>]*>/g, '').trim();
      }
    }

    throw new Error(
      `Intercom: no bot reply after ${this.maxPollAttempts} poll attempts ` +
        `(${this.maxPollAttempts * this.pollIntervalMs / 1000}s)`,
    );
  }

  override async healthCheck(): Promise<boolean> {
    try {
      const { data } = await this.client.get('/me');
      return !!(data as Record<string, unknown>).id;
    } catch {
      return false;
    }
  }

  override resetSession(): void {
    this.conversationId = null;
    // Keep the same contact across resets to avoid creating too many leads
  }

  override async close(): Promise<void> {
    // Clean up: close the conversation if open
    if (this.conversationId) {
      try {
        await this.client.post(`/conversations/${this.conversationId}/parts`, {
          message_type: 'close',
          type: 'admin',
          admin_id: 'system',
        });
      } catch {
        // Best effort cleanup
      }
    }
  }
}
