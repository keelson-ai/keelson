import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';


/**
 * Generic HTTP adapter for any OpenAI-compatible chat completions endpoint.
 * Appends /v1/chat/completions to the base URL.
 */
export class GenericHTTPAdapter extends BaseAdapter {
  private readonly defaultModel: string;

  constructor(config: AdapterConfig) {
    const baseUrl = config.baseUrl.replace(/\/+$/, '') + '/v1/chat/completions';
    super({
      ...config,
      baseUrl,
      headers: {
        ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
        ...config.headers,
      },
    });
    this.defaultModel = config.model ?? 'gpt-4o';
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const model = this.config.model && this.config.model !== 'default' ? this.config.model : this.defaultModel;
    const start = performance.now();

    const payload: Record<string, unknown> = { model, messages };

    const { data } = await this.client.post('', payload);
    const latencyMs = Math.round(performance.now() - start);

    const content: string = data.choices?.[0]?.message?.content ?? '';
    return { content, raw: data, latencyMs };
  }
}
