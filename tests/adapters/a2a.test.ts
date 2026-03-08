import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { A2AAdapter } from '../../src/adapters/a2a.js';
import type { AdapterConfig } from '../../src/types/index.js';

const BASE = 'https://a2a.example.com';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'a2a', baseUrl: BASE, ...overrides };
}

describe('A2AAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('sends tasks/send and extracts artifact text', async () => {
    nock(BASE)
      .post('/', (body: Record<string, unknown>) => body.method === 'tasks/send')
      .reply(200, {
        jsonrpc: '2.0',
        id: 'req-1',
        result: {
          artifacts: [{ parts: [{ type: 'text', text: 'A2A response' }] }],
        },
      });

    const adapter = new A2AAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'Hello' }]);
    expect(result.content).toBe('A2A response');
  });

  it('extracts last user message only', async () => {
    nock(BASE)
      .post('/', (body: Record<string, unknown>) => {
        const params = body.params as { message: { parts: Array<{ text: string }> } };
        return params.message.parts[0].text === 'second message';
      })
      .reply(200, {
        jsonrpc: '2.0',
        id: 'req-1',
        result: { artifacts: [{ parts: [{ type: 'text', text: 'ok' }] }] },
      });

    const adapter = new A2AAdapter(makeConfig());
    await adapter.send([
      { role: 'user', content: 'first message' },
      { role: 'assistant', content: 'response' },
      { role: 'user', content: 'second message' },
    ]);
  });

  it('falls back to status message when no artifacts', async () => {
    nock(BASE)
      .post('/')
      .reply(200, {
        jsonrpc: '2.0',
        id: 'req-1',
        result: {
          status: {
            message: {
              parts: [{ type: 'text', text: 'Status response' }],
            },
          },
        },
      });

    const adapter = new A2AAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('Status response');
  });

  it('throws on JSON-RPC error', async () => {
    nock(BASE)
      .post('/')
      .reply(200, {
        jsonrpc: '2.0',
        id: 'req-1',
        error: { code: -32000, message: 'Agent unavailable' },
      });

    const adapter = new A2AAdapter(makeConfig());
    await expect(adapter.send([{ role: 'user', content: 'test' }])).rejects.toThrow(
      'A2A error -32000: Agent unavailable',
    );
  });

  it('healthCheck discovers agent card', async () => {
    nock(BASE).get('/.well-known/agent.json').reply(200, { name: 'TestAgent', version: '1.0' });

    const adapter = new A2AAdapter(makeConfig());
    expect(await adapter.healthCheck()).toBe(true);
  });

  it('healthCheck returns false when discovery fails', async () => {
    nock(BASE).get('/.well-known/agent.json').reply(404);

    const adapter = new A2AAdapter(makeConfig({ retryAttempts: 0 }));
    expect(await adapter.healthCheck()).toBe(false);
  });

  it('includes bearer auth when api key provided', async () => {
    nock(BASE)
      .post('/')
      .matchHeader('Authorization', 'Bearer my-key')
      .reply(200, {
        jsonrpc: '2.0',
        id: 'req-1',
        result: { artifacts: [{ parts: [{ type: 'text', text: 'ok' }] }] },
      });

    const adapter = new A2AAdapter(makeConfig({ apiKey: 'my-key' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('handles empty result gracefully', async () => {
    nock(BASE).post('/').reply(200, { jsonrpc: '2.0', id: 'req-1', result: {} });

    const adapter = new A2AAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('');
  });
});
