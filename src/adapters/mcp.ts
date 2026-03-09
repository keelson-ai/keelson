import { BaseAdapter } from './base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

const MCP_JSONRPC_VERSION = '2.0';
const MCP_PROTOCOL_VERSION = '2025-03-26';

/**
 * MCP (Model Context Protocol) adapter. Communicates via JSON-RPC 2.0 over HTTP.
 * Performs protocol initialization handshake, then invokes tools/call.
 */
export class MCPAdapter extends BaseAdapter {
  private initialized = false;
  private requestId = 0;
  private readonly toolName: string;

  constructor(config: AdapterConfig) {
    super({
      ...config,
      baseUrl: config.baseUrl.replace(/\/+$/, ''),
      headers: {
        ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
        ...config.headers,
      },
    });
    this.toolName = config.toolName ?? 'chat';
  }

  private nextId(): number {
    return ++this.requestId;
  }

  private async ensureInitialized(): Promise<void> {
    if (this.initialized) return;

    // Step 1: Initialize handshake
    await this.client.post('', {
      jsonrpc: MCP_JSONRPC_VERSION,
      id: this.nextId(),
      method: 'initialize',
      params: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'keelson', version: '0.5.0' },
      },
    });

    // Step 2: Send initialized notification (no id)
    await this.client.post('', {
      jsonrpc: MCP_JSONRPC_VERSION,
      method: 'notifications/initialized',
    });

    this.initialized = true;
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    await this.ensureInitialized();

    const model = this.config.model && this.config.model !== 'default' ? this.config.model : undefined;
    const args: Record<string, unknown> = { messages };
    if (model) args.model = model;

    const start = performance.now();
    const { data } = await this.client.post('', {
      jsonrpc: MCP_JSONRPC_VERSION,
      id: this.nextId(),
      method: 'tools/call',
      params: {
        name: this.toolName,
        arguments: args,
      },
    });
    const latencyMs = Math.round(performance.now() - start);

    if (data.error) {
      throw new Error(`MCP error ${data.error.code}: ${data.error.message}`);
    }

    const content = this.extractContent(data.result?.content ?? []);
    return { content, raw: data, latencyMs };
  }

  private extractContent(blocks: Array<{ type: string; text?: string }>): string {
    return blocks
      .filter((b) => b.type === 'text' && b.text)
      .map((b) => b.text ?? '')
      .join('');
  }

  override async healthCheck(): Promise<boolean> {
    try {
      const prevInitialized = this.initialized;
      const prevRequestId = this.requestId;
      this.initialized = false;
      await this.ensureInitialized();
      // Revert state so health check is non-destructive
      this.initialized = prevInitialized;
      this.requestId = prevRequestId;
      return true;
    } catch {
      return false;
    }
  }
}
