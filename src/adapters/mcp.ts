import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

import { BaseAdapter } from './base.js';
import { adapterLogger } from '../core/logger.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

/**
 * MCP (Model Context Protocol) adapter using the official SDK.
 * Replaces manual JSON-RPC 2.0 handling with SDK-managed protocol negotiation.
 */
export class MCPAdapter extends BaseAdapter {
  private mcpClient: Client | null = null;
  private transport: StreamableHTTPClientTransport | null = null;
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

  private async ensureInitialized(): Promise<void> {
    if (this.mcpClient) return;

    this.mcpClient = new Client({ name: 'keelson', version: '1.0.0' });
    this.transport = new StreamableHTTPClientTransport(new URL(this.config.baseUrl));
    await this.mcpClient.connect(this.transport);
    adapterLogger.debug({ url: this.config.baseUrl }, 'MCP client connected');
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    await this.ensureInitialized();

    const model = this.resolveModel('');
    const args: Record<string, unknown> = { messages };
    if (model) args.model = model;

    const start = performance.now();
    // mcpClient is guaranteed non-null after ensureInitialized()
    const client = this.mcpClient as Client;
    const result = await client.callTool({
      name: this.toolName,
      arguments: args,
    });
    const latencyMs = Math.round(performance.now() - start);

    const content = this.extractContent(result.content as Array<{ type: string; text?: string }> ?? []);
    return { content, raw: result, latencyMs };
  }

  private extractContent(blocks: Array<{ type: string; text?: string }>): string {
    return blocks
      .filter((b) => b.type === 'text' && b.text)
      .map((b) => b.text ?? '')
      .join('');
  }

  override async healthCheck(): Promise<boolean> {
    const prevClient = this.mcpClient;
    const prevTransport = this.transport;
    try {
      // Attempt to initialize — if it connects, the server is healthy
      this.mcpClient = null;
      this.transport = null;

      await this.ensureInitialized();

      // Revert to previous state if it was already initialized
      // ensureInitialized() mutates this.mcpClient, but TS can't track it
      const newClient = this.mcpClient as Client | null;
      if (prevClient) {
        this.mcpClient = prevClient;
        this.transport = prevTransport;
        await newClient?.close();
      }

      return true;
    } catch {
      // Restore previous connection state on failure
      this.mcpClient = prevClient;
      this.transport = prevTransport;
      return false;
    }
  }

  override async close(): Promise<void> {
    if (this.mcpClient) {
      await this.mcpClient.close();
      this.mcpClient = null;
      this.transport = null;
    }
  }
}
