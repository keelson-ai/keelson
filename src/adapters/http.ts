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
    const model = this.resolveModel(this.defaultModel);
    const { data, latencyMs } = await this.timedPost('', { model, messages });
    const content: string =
      (data as Record<string, unknown> & { choices?: Array<{ message?: { content?: string } }> }).choices?.[0]?.message
        ?.content ?? '';
    return { content, raw: data, latencyMs };
  }
}
