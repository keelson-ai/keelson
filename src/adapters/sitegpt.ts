import crypto from 'node:crypto';

import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

const WIDGET_BASE = 'https://widget.sitegpt.ai';
const PK_HOST = 'pk.sitegpt.ai';
const API_BASE = 'https://sitegpt.ai/api/v0';

/**
 * SiteGPT adapter with dual mode:
 * - API mode (apiKey provided): REST API calls
 * - Widget mode (no apiKey): HTTP thread creation + WebSocket streaming
 */
export class SiteGPTAdapter extends BaseAdapter {
  private readonly chatbotId: string;
  private sessionId: string;
  private threadId: string | null = null;

  constructor(config: AdapterConfig) {
    if (!config.chatbotId) {
      throw new Error('SiteGPT adapter requires chatbotId in config');
    }
    super({
      ...config,
      baseUrl: config.apiKey ? API_BASE : WIDGET_BASE,
      headers: {
        ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
        ...config.headers,
      },
    });
    this.chatbotId = config.chatbotId;
    this.sessionId = crypto.randomUUID();
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const message = lastUser?.content ?? '';

    if (this.config.apiKey) {
      return this.sendApi(message);
    }
    return this.sendWidget(message);
  }

  private async sendApi(message: string): Promise<AdapterResponse> {
    const payload: Record<string, unknown> = {
      message,
      from: 'USER',
    };
    if (this.threadId) {
      payload.threadId = this.threadId;
    }

    const { data, latencyMs } = await this.timedPost<Record<string, unknown>>(
      `/chatbots/${this.chatbotId}/message`,
      payload,
    );

    const inner = data.data as { threadId?: string; message?: { answer?: { text?: string } } } | undefined;
    this.threadId = inner?.threadId ?? this.threadId;
    const content: string = inner?.message?.answer?.text ?? '';
    return { content, raw: data, latencyMs };
  }

  private async createThread(): Promise<string> {
    if (this.threadId) return this.threadId;

    const { headers } = await this.client.post(
      `/c/${this.chatbotId}?_data=routes/c.$chatbotId`,
      new URLSearchParams({
        _action: 'START_CONVERSATION',
        sessionId: this.sessionId,
      }).toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        maxRedirects: 0,
        validateStatus: (s) => s < 400,
      },
    );

    const redirect = headers['x-remix-redirect'] as string | undefined;
    if (!redirect) throw new Error('SiteGPT: no redirect header in thread creation response');

    // Extract thread ID from redirect URL path
    const threadId = redirect.split('/').pop();
    if (!threadId) throw new Error('SiteGPT: could not extract thread ID from redirect');

    this.threadId = threadId;
    return threadId;
  }

  private async sendWidget(message: string): Promise<AdapterResponse> {
    const threadId = await this.createThread();
    const start = performance.now();

    return new Promise<AdapterResponse>((resolve, reject) => {
      const wsUrl = `wss://${PK_HOST}/parties/thread/${threadId}?_pk=${this.sessionId}`;
      const ws = new WebSocket(wsUrl);
      let content = '';
      const timeout = setTimeout(() => {
        ws.close();
        reject(new Error('SiteGPT WebSocket timeout'));
      }, this.config.timeout ?? 60_000);

      ws.onopen = () => {
        ws.send(
          JSON.stringify({
            event: 'NEW_MESSAGE',
            data: {
              from: 'USER',
              message,
              sessionId: this.sessionId,
              chatbotId: this.chatbotId,
            },
          }),
        );
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(String(event.data));
          if (parsed.event === 'AI_STREAM_UPDATED') {
            content = parsed.data?.message?.answer ?? content;
          } else if (parsed.event === 'AI_STREAM_ENDED') {
            clearTimeout(timeout);
            content = parsed.data?.message?.answer?.text ?? content;
            ws.close();
            const latencyMs = Math.round(performance.now() - start);
            resolve({ content, raw: parsed, latencyMs });
          } else if (parsed.event === 'ERROR') {
            clearTimeout(timeout);
            ws.close();
            reject(new Error(`SiteGPT error: ${parsed.data?.message ?? 'unknown'}`));
          }
        } catch {
          // Ignore non-JSON messages
        }
      };

      ws.onerror = (err) => {
        clearTimeout(timeout);
        reject(new Error(`SiteGPT WebSocket error: ${err}`));
      };
    });
  }

  override resetSession(): void {
    this.threadId = null;
    this.sessionId = crypto.randomUUID();
  }
}
