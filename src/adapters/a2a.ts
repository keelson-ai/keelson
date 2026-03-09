import crypto from 'node:crypto';

import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

/**
 * Google Agent-to-Agent (A2A) protocol adapter.
 * Uses JSON-RPC 2.0 tasks/send to communicate with A2A-compatible agents.
 */
export class A2AAdapter extends BaseAdapter {
  private agentCard: Record<string, unknown> | null = null;

  constructor(config: AdapterConfig) {
    super({
      ...config,
      baseUrl: config.baseUrl.replace(/\/+$/, ''),
      headers: {
        ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
        ...config.headers,
      },
    });
  }

  private async discoverAgent(): Promise<Record<string, unknown>> {
    if (!this.agentCard) {
      const { data } = await this.client.get('/.well-known/agent.json');
      this.agentCard = data;
    }
    return this.agentCard as Record<string, unknown>;
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    // Extract last user message
    const lastUser = messages.filter((m) => m.role === 'user').pop();
    const userMessage = lastUser?.content ?? '';

    const taskId = crypto.randomBytes(8).toString('hex');
    const requestId = crypto.randomBytes(4).toString('hex');

    const { data, latencyMs } = await this.timedPost<Record<string, unknown>>('', {
      jsonrpc: '2.0',
      id: requestId,
      method: 'tasks/send',
      params: {
        id: taskId,
        message: {
          role: 'user',
          parts: [{ type: 'text', text: userMessage }],
        },
      },
    });

    if (data.error) {
      const err = data.error as { code: number; message: string };
      throw new Error(`A2A error ${err.code}: ${err.message}`);
    }

    const content = this.extractResponse((data.result ?? {}) as Record<string, unknown>);
    return { content, raw: data, latencyMs };
  }

  private extractResponse(result: Record<string, unknown>): string {
    // Try artifacts first
    const artifacts = result.artifacts as Array<{ parts?: Array<{ type: string; text?: string }> }> | undefined;
    if (artifacts?.length) {
      const texts: string[] = [];
      for (const artifact of artifacts) {
        for (const part of artifact.parts ?? []) {
          if (part.type === 'text' && part.text) {
            texts.push(part.text);
          }
        }
      }
      if (texts.length) return texts.join('');
    }

    // Fallback to status message
    const status = result.status as { message?: { parts?: Array<{ type: string; text?: string }> } } | undefined;
    if (status?.message?.parts) {
      return status.message.parts
        .filter((p) => p.type === 'text' && p.text)
        .map((p) => p.text ?? '')
        .join('');
    }

    return '';
  }

  override async healthCheck(): Promise<boolean> {
    try {
      const card = await this.discoverAgent();
      return 'name' in card;
    } catch {
      return false;
    }
  }
}
