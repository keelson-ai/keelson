import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { AdapterConfig } from '../../src/types/index.js';

// Mock the MCP SDK before importing the adapter
const mockConnect = vi.fn().mockResolvedValue(undefined);
const mockCallTool = vi.fn();
const mockClose = vi.fn().mockResolvedValue(undefined);

vi.mock('@modelcontextprotocol/sdk/client/index.js', () => ({
  Client: class MockClient {
    connect = mockConnect;
    callTool = mockCallTool;
    close = mockClose;
  },
}));

vi.mock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => ({
  // eslint-disable-next-line @typescript-eslint/no-extraneous-class
  StreamableHTTPClientTransport: class MockTransport {},
}));

// Import after mocking
const { MCPAdapter } = await import('../../src/adapters/mcp.js');

const BASE = 'https://mcp.example.com';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'mcp', baseUrl: BASE, ...overrides };
}

describe('MCPAdapter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('initializes and sends tools/call', async () => {
    mockCallTool.mockResolvedValue({
      content: [{ type: 'text', text: 'MCP response' }],
    });

    const adapter = new MCPAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);

    expect(result.content).toBe('MCP response');
    expect(mockConnect).toHaveBeenCalledTimes(1);
    expect(mockCallTool).toHaveBeenCalledWith({
      name: 'chat',
      arguments: { messages: [{ role: 'user', content: 'test' }] },
    });
  });

  it('only initializes once', async () => {
    mockCallTool.mockResolvedValue({
      content: [{ type: 'text', text: 'ok' }],
    });

    const adapter = new MCPAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'msg1' }]);
    await adapter.send([{ role: 'user', content: 'msg2' }]);

    // connect should only be called once
    expect(mockConnect).toHaveBeenCalledTimes(1);
    expect(mockCallTool).toHaveBeenCalledTimes(2);
  });

  it('uses custom tool name', async () => {
    mockCallTool.mockResolvedValue({
      content: [{ type: 'text', text: 'ok' }],
    });

    const adapter = new MCPAdapter(makeConfig({ toolName: 'ask' }));
    await adapter.send([{ role: 'user', content: 'test' }]);

    expect(mockCallTool).toHaveBeenCalledWith(expect.objectContaining({ name: 'ask' }));
  });

  it('throws on callTool error', async () => {
    mockCallTool.mockRejectedValue(new Error('MCP error -32600: Invalid request'));

    const adapter = new MCPAdapter(makeConfig());
    await expect(adapter.send([{ role: 'user', content: 'test' }])).rejects.toThrow(
      'MCP error -32600: Invalid request',
    );
  });

  it('extracts multiple text blocks', async () => {
    mockCallTool.mockResolvedValue({
      content: [
        { type: 'text', text: 'Part 1. ' },
        { type: 'image', data: 'xxx' },
        { type: 'text', text: 'Part 2.' },
      ],
    });

    const adapter = new MCPAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('Part 1. Part 2.');
  });

  it('healthCheck returns true when initialization succeeds', async () => {
    const adapter = new MCPAdapter(makeConfig());
    expect(await adapter.healthCheck()).toBe(true);
    expect(mockConnect).toHaveBeenCalled();
  });

  it('healthCheck returns false on failure', async () => {
    mockConnect.mockRejectedValueOnce(new Error('connection refused'));

    const adapter = new MCPAdapter(makeConfig({ retryAttempts: 0 }));
    expect(await adapter.healthCheck()).toBe(false);
  });
});
