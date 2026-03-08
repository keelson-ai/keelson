import { describe, expect, it } from 'vitest';

import { BaseAdapter } from '../../src/adapters/base.js';
import { createAdapter, registerAdapter } from '../../src/adapters/index.js';
import type { AdapterResponse, Turn } from '../../src/types/index.js';

describe('createAdapter factory', () => {
  it('creates openai adapter', () => {
    const adapter = createAdapter({ type: 'openai', baseUrl: 'https://api.openai.com/v1/chat/completions' });
    expect(adapter).toBeDefined();
  });

  it('creates http adapter', () => {
    const adapter = createAdapter({ type: 'http', baseUrl: 'https://api.example.com' });
    expect(adapter).toBeDefined();
  });

  it('creates anthropic adapter', () => {
    const adapter = createAdapter({
      type: 'anthropic',
      baseUrl: 'https://api.anthropic.com/v1/messages',
      apiKey: 'test',
    });
    expect(adapter).toBeDefined();
  });

  it('creates langgraph adapter', () => {
    const adapter = createAdapter({ type: 'langgraph', baseUrl: 'https://langgraph.example.com' });
    expect(adapter).toBeDefined();
  });

  it('creates mcp adapter', () => {
    const adapter = createAdapter({ type: 'mcp', baseUrl: 'https://mcp.example.com' });
    expect(adapter).toBeDefined();
  });

  it('creates a2a adapter', () => {
    const adapter = createAdapter({ type: 'a2a', baseUrl: 'https://a2a.example.com' });
    expect(adapter).toBeDefined();
  });

  it('creates crewai adapter', () => {
    const adapter = createAdapter({ type: 'crewai', baseUrl: 'http://localhost:8001' });
    expect(adapter).toBeDefined();
  });

  it('creates langchain adapter', () => {
    const adapter = createAdapter({ type: 'langchain', baseUrl: 'http://localhost:8002' });
    expect(adapter).toBeDefined();
  });

  it('creates sitegpt adapter', () => {
    const adapter = createAdapter({ type: 'sitegpt', baseUrl: 'https://widget.sitegpt.ai', chatbotId: 'test-bot' });
    expect(adapter).toBeDefined();
  });

  it('throws on unknown adapter type', () => {
    expect(() => createAdapter({ type: 'nonexistent', baseUrl: 'https://x.com' })).toThrow(
      'Unknown adapter type: "nonexistent"',
    );
  });

  it('registers custom adapter', () => {
    class CustomAdapter extends BaseAdapter {
      async send(_messages: Turn[]): Promise<AdapterResponse> {
        return { content: 'custom', raw: {}, latencyMs: 0 };
      }
    }

    registerAdapter('custom', CustomAdapter);
    const adapter = createAdapter({ type: 'custom', baseUrl: 'https://custom.example.com' });
    expect(adapter).toBeInstanceOf(CustomAdapter);
  });
});
