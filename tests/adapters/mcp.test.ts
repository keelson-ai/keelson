import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { MCPAdapter } from '../../src/adapters/mcp.js';
import type { AdapterConfig } from '../../src/types/index.js';

const BASE = 'https://mcp.example.com';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'mcp', baseUrl: BASE, ...overrides };
}

describe('MCPAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  function mockInitialize(): void {
    // Initialize request
    nock(BASE)
      .post('/', (body: Record<string, unknown>) => body.method === 'initialize')
      .reply(200, {
        jsonrpc: '2.0',
        id: 1,
        result: { protocolVersion: '2025-03-26', capabilities: {} },
      });

    // Initialized notification
    nock(BASE)
      .post('/', (body: Record<string, unknown>) => body.method === 'notifications/initialized')
      .reply(200, {});
  }

  it('initializes and sends tools/call', async () => {
    mockInitialize();

    nock(BASE)
      .post('/', (body: Record<string, unknown>) => body.method === 'tools/call')
      .reply(200, {
        jsonrpc: '2.0',
        id: 3,
        result: {
          content: [{ type: 'text', text: 'MCP response' }],
        },
      });

    const adapter = new MCPAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('MCP response');
  });

  it('only initializes once', async () => {
    mockInitialize();

    // Two tools/call requests
    nock(BASE)
      .post('/', (body: Record<string, unknown>) => body.method === 'tools/call')
      .twice()
      .reply(200, {
        jsonrpc: '2.0',
        id: 3,
        result: { content: [{ type: 'text', text: 'ok' }] },
      });

    const adapter = new MCPAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'msg1' }]);
    await adapter.send([{ role: 'user', content: 'msg2' }]);
  });

  it('uses custom tool name', async () => {
    mockInitialize();

    nock(BASE)
      .post('/', (body: Record<string, unknown>) => {
        const params = body.params as { name: string };
        return body.method === 'tools/call' && params.name === 'ask';
      })
      .reply(200, {
        jsonrpc: '2.0',
        id: 3,
        result: { content: [{ type: 'text', text: 'ok' }] },
      });

    const adapter = new MCPAdapter(makeConfig({ toolName: 'ask' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('throws on JSON-RPC error', async () => {
    mockInitialize();

    nock(BASE)
      .post('/', (body: Record<string, unknown>) => body.method === 'tools/call')
      .reply(200, {
        jsonrpc: '2.0',
        id: 3,
        error: { code: -32600, message: 'Invalid request' },
      });

    const adapter = new MCPAdapter(makeConfig());
    await expect(adapter.send([{ role: 'user', content: 'test' }])).rejects.toThrow(
      'MCP error -32600: Invalid request',
    );
  });

  it('extracts multiple text blocks', async () => {
    mockInitialize();

    nock(BASE)
      .post('/', (body: Record<string, unknown>) => body.method === 'tools/call')
      .reply(200, {
        jsonrpc: '2.0',
        id: 3,
        result: {
          content: [
            { type: 'text', text: 'Part 1. ' },
            { type: 'image', data: 'xxx' },
            { type: 'text', text: 'Part 2.' },
          ],
        },
      });

    const adapter = new MCPAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('Part 1. Part 2.');
  });

  it('healthCheck returns true when initialization succeeds', async () => {
    // Health check does initialize + revert
    mockInitialize();

    const adapter = new MCPAdapter(makeConfig());
    expect(await adapter.healthCheck()).toBe(true);
  });

  it('healthCheck returns false on failure', async () => {
    nock(BASE).post('/').reply(500);

    const adapter = new MCPAdapter(makeConfig({ retryAttempts: 0 }));
    expect(await adapter.healthCheck()).toBe(false);
  });
});
