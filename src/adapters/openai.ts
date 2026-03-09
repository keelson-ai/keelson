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
    const model = this.resolveModel('gpt-4o');
    const { data, latencyMs } = await this.timedPost('', { model, messages });
    const content: string =
      (data as Record<string, unknown> & { choices?: Array<{ message?: { content?: string } }> }).choices?.[0]?.message
        ?.content ?? '';
    return { content, raw: data, latencyMs };
  }
}
