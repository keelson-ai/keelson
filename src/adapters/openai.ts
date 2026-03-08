import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

export class OpenAIAdapter extends BaseAdapter {
  constructor(config: AdapterConfig) {
    const baseUrl = config.baseUrl.replace(/\/+$/, '');
    super({
      ...config,
      baseUrl,
      headers: {
        ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
        ...config.headers,
      },
    });
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const model = this.config.model && this.config.model !== 'default' ? this.config.model : 'gpt-4o';
    const start = performance.now();

    const payload: Record<string, unknown> = { model, messages };

    const { data } = await this.client.post('', payload);
    const latencyMs = Math.round(performance.now() - start);

    const content: string = data.choices?.[0]?.message?.content ?? '';
    return { content, raw: data, latencyMs };
  }
}
