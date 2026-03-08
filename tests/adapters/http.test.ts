import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { GenericHTTPAdapter } from '../../src/adapters/http.js';
import type { AdapterConfig } from '../../src/types/index.js';

const BASE = 'https://api.example.com';
const ENDPOINT = `${BASE}/v1/chat/completions`;

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'http', baseUrl: BASE, ...overrides };
}

describe('GenericHTTPAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('appends /v1/chat/completions to base URL', async () => {
    nock(ENDPOINT)
      .post('')
      .reply(200, { choices: [{ message: { content: 'ok' } }] });

    const adapter = new GenericHTTPAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('ok');
  });

  it('uses default model gpt-4o', async () => {
    nock(ENDPOINT)
      .post('', (body: Record<string, unknown>) => body.model === 'gpt-4o')
      .reply(200, { choices: [{ message: { content: 'ok' } }] });

    const adapter = new GenericHTTPAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('uses custom default model', async () => {
    nock(ENDPOINT)
      .post('', (body: Record<string, unknown>) => body.model === 'llama-3')
      .reply(200, { choices: [{ message: { content: 'ok' } }] });

    const adapter = new GenericHTTPAdapter(makeConfig({ model: 'llama-3' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('works without api key', async () => {
    nock(ENDPOINT)
      .post('')
      .reply(200, { choices: [{ message: { content: 'ok' } }] });

    const adapter = new GenericHTTPAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('ok');
  });

  it('includes authorization when api key provided', async () => {
    nock(ENDPOINT)
      .post('')
      .matchHeader('Authorization', 'Bearer test-key')
      .reply(200, { choices: [{ message: { content: 'ok' } }] });

    const adapter = new GenericHTTPAdapter(makeConfig({ apiKey: 'test-key' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('handles missing content in response', async () => {
    nock(ENDPOINT)
      .post('')
      .reply(200, { choices: [{ message: {} }] });

    const adapter = new GenericHTTPAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('');
  });
});
