import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_VERSION = '2023-06-01';
const DEFAULT_MAX_TOKENS = 4096;

export class AnthropicAdapter extends BaseAdapter {
  constructor(config: AdapterConfig) {
    super({
      ...config,
      baseUrl: config.baseUrl || ANTHROPIC_API_URL,
      headers: {
        'x-api-key': config.apiKey ?? '',
        'anthropic-version': ANTHROPIC_VERSION,
        ...config.headers,
      },
    });
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const model = this.config.model && this.config.model !== 'default' ? this.config.model : 'claude-sonnet-4-6';

    // Extract system messages into top-level parameter
    const systemParts: string[] = [];
    const apiMessages: Turn[] = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        systemParts.push(msg.content);
      } else {
        apiMessages.push(msg);
      }
    }

    const payload: Record<string, unknown> = {
      model,
      max_tokens: DEFAULT_MAX_TOKENS,
      messages: apiMessages,
    };

    if (systemParts.length > 0) {
      payload.system = systemParts.join('\n\n');
    }

    const start = performance.now();
    const { data } = await this.client.post('', payload);
    const latencyMs = Math.round(performance.now() - start);

    // Extract text from content blocks
    const content = this.extractContent(data.content ?? []);
    return { content, raw: data, latencyMs };
  }

  private extractContent(blocks: Array<{ type: string; text?: string }>): string {
    return blocks
      .filter((b) => b.type === 'text' && b.text)
      .map((b) => b.text!)
      .join('');
  }
}
