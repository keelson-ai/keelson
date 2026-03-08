import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';


/**
 * LangGraph Platform adapter. Stateful: maintains a thread across calls.
 * Communicates via /threads/{id}/runs/wait endpoint.
 */
export class LangGraphAdapter extends BaseAdapter {
  private threadId: string | null = null;
  private readonly assistantId: string;

  constructor(config: AdapterConfig) {
    const baseUrl = config.baseUrl.replace(/\/+$/, '');
    super({
      ...config,
      baseUrl,
      timeout: config.timeout ?? 120_000,
      headers: {
        ...(config.apiKey ? { 'x-api-key': config.apiKey } : {}),
        ...config.headers,
      },
    });
    this.assistantId = config.assistantId ?? 'agent';
  }

  private async ensureThread(): Promise<string> {
    if (!this.threadId) {
      const { data } = await this.client.post('/threads', {});
      this.threadId = data.thread_id;
    }
    return this.threadId!;
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const threadId = await this.ensureThread();
    const model = this.config.model && this.config.model !== 'default' ? this.config.model : undefined;

    const payload: Record<string, unknown> = {
      input: { messages },
      assistant_id: this.assistantId,
    };

    if (model) {
      payload.config = { configurable: { model } };
    }

    const start = performance.now();
    const { data } = await this.client.post(`/threads/${threadId}/runs/wait`, payload);
    const latencyMs = Math.round(performance.now() - start);

    const content = this.extractAiResponse(data);
    return { content, raw: data, latencyMs };
  }

  private extractAiResponse(data: Record<string, unknown>): string {
    const messages = (data.messages ?? (data.output as Record<string, unknown>)?.messages) as
      | Array<Record<string, unknown>>
      | undefined;

    if (!messages?.length) return '';

    // Find last AI/assistant message
    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i];
      if (msg.type === 'ai' || msg.role === 'assistant') {
        const content = msg.content;
        if (typeof content === 'string') return content;
        if (Array.isArray(content)) {
          return (content as Array<{ type: string; text?: string }>)
            .filter((b) => b.type === 'text' && b.text)
            .map((b) => b.text!)
            .join('');
        }
      }
    }

    return '';
  }

  override resetSession(): void {
    this.threadId = null;
  }
}
