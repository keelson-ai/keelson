import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { BaseAdapter } from '../../src/adapters/base.js';
import type { AdapterConfig, AdapterResponse, Turn } from '../../src/types/index.js';

const TEST_URL = 'http://test-target.example.com';

class TestAdapter extends BaseAdapter {
  async send(messages: Turn[]): Promise<AdapterResponse> {
    return this.withRetry(async () => {
      const start = performance.now();
      const { data } = await this.client.post('/api/chat', { messages });
      return {
        content: data.response,
        raw: data,
        latencyMs: performance.now() - start,
      };
    });
  }
}

function makeConfig(overrides?: Partial<AdapterConfig>): AdapterConfig {
  return {
    type: 'test',
    baseUrl: TEST_URL,
    retryDelay: 10,
    ...overrides,
  };
}

describe('BaseAdapter retry logic', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('retries on 429 and succeeds', async () => {
    nock(TEST_URL).post('/api/chat').reply(429, 'rate limited', { 'Retry-After': '0' });

    nock(TEST_URL).post('/api/chat').reply(200, { response: 'ok' });

    const adapter = new TestAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'hi' }]);
    expect(result.content).toBe('ok');
  });

  it('retries on 503 with exponential backoff', async () => {
    nock(TEST_URL).post('/api/chat').reply(503, 'unavailable');

    nock(TEST_URL).post('/api/chat').reply(200, { response: 'recovered' });

    const adapter = new TestAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'hi' }]);
    expect(result.content).toBe('recovered');
  });

  it('does not retry on 400', async () => {
    nock(TEST_URL).post('/api/chat').reply(400, { error: 'bad request' });

    const adapter = new TestAdapter(makeConfig());
    await expect(adapter.send([{ role: 'user', content: 'hi' }])).rejects.toThrow();
    expect(nock.pendingMocks()).toHaveLength(0);
  });

  it('does not retry on 401', async () => {
    nock(TEST_URL).post('/api/chat').reply(401, { error: 'unauthorized' });

    const adapter = new TestAdapter(makeConfig());
    await expect(adapter.send([{ role: 'user', content: 'hi' }])).rejects.toThrow();
  });

  it('does not retry on 404', async () => {
    nock(TEST_URL).post('/api/chat').reply(404, { error: 'not found' });

    const adapter = new TestAdapter(makeConfig());
    await expect(adapter.send([{ role: 'user', content: 'hi' }])).rejects.toThrow();
  });

  it('throws after max retries exhausted', async () => {
    nock(TEST_URL).post('/api/chat').times(4).reply(429, 'rate limited', { 'Retry-After': '0' });

    const adapter = new TestAdapter(makeConfig({ retryAttempts: 3 }));
    await expect(adapter.send([{ role: 'user', content: 'hi' }])).rejects.toThrow();
  });

  it('healthCheck returns true on success', async () => {
    nock(TEST_URL).post('/api/chat').reply(200, { response: 'pong' });

    const adapter = new TestAdapter(makeConfig());
    const healthy = await adapter.healthCheck();
    expect(healthy).toBe(true);
  });

  it('healthCheck returns false on failure', async () => {
    nock(TEST_URL).post('/api/chat').times(4).reply(500, 'error');

    const adapter = new TestAdapter(makeConfig({ retryAttempts: 0 }));
    const healthy = await adapter.healthCheck();
    expect(healthy).toBe(false);
  });
});
