import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { OpenAIAdapter } from '../../src/adapters/openai.js';
import type { AdapterConfig } from '../../src/types/index.js';

const BASE_URL = 'https://api.openai.com/v1/chat/completions';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'openai', baseUrl: BASE_URL, apiKey: 'sk-test-key', ...overrides };
}

describe('OpenAIAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('sends messages and parses response', async () => {
    nock(BASE_URL)
      .post('')
      .reply(200, {
        choices: [{ message: { content: 'Hello!' } }],
      });

    const adapter = new OpenAIAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'Hi' }]);

    expect(result.content).toBe('Hello!');
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    expect(result.raw).toBeDefined();
  });

  it('sends Authorization header', async () => {
    nock(BASE_URL)
      .post('')
      .matchHeader('Authorization', 'Bearer sk-test-key')
      .reply(200, {
        choices: [{ message: { content: 'ok' } }],
      });

    const adapter = new OpenAIAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('uses default model gpt-4o when model is "default"', async () => {
    nock(BASE_URL)
      .post('', (body: Record<string, unknown>) => body.model === 'gpt-4o')
      .reply(200, {
        choices: [{ message: { content: 'ok' } }],
      });

    const adapter = new OpenAIAdapter(makeConfig({ model: 'default' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('uses custom model when specified', async () => {
    nock(BASE_URL)
      .post('', (body: Record<string, unknown>) => body.model === 'gpt-3.5-turbo')
      .reply(200, {
        choices: [{ message: { content: 'ok' } }],
      });

    const adapter = new OpenAIAdapter(makeConfig({ model: 'gpt-3.5-turbo' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('handles empty choices gracefully', async () => {
    nock(BASE_URL).post('').reply(200, { choices: [] });

    const adapter = new OpenAIAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);

    expect(result.content).toBe('');
  });

  it('strips trailing slashes from URL', async () => {
    nock(BASE_URL)
      .post('')
      .reply(200, { choices: [{ message: { content: 'ok' } }] });

    const adapter = new OpenAIAdapter(makeConfig({ baseUrl: BASE_URL + '///' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('passes messages array to API', async () => {
    const messages = [
      { role: 'system' as const, content: 'You are helpful.' },
      { role: 'user' as const, content: 'Hello' },
    ];

    nock(BASE_URL)
      .post('', (body: Record<string, unknown>) => {
        const msgs = body.messages as Array<{ role: string; content: string }>;
        return msgs.length === 2 && msgs[0].role === 'system' && msgs[1].role === 'user';
      })
      .reply(200, { choices: [{ message: { content: 'Hi!' } }] });

    const adapter = new OpenAIAdapter(makeConfig());
    const result = await adapter.send(messages);
    expect(result.content).toBe('Hi!');
  });

  it('healthCheck returns true on success', async () => {
    nock(BASE_URL)
      .post('')
      .reply(200, { choices: [{ message: { content: 'pong' } }] });

    const adapter = new OpenAIAdapter(makeConfig());
    expect(await adapter.healthCheck()).toBe(true);
  });

  it('healthCheck returns false on error', async () => {
    nock(BASE_URL).post('').reply(500);

    const adapter = new OpenAIAdapter(makeConfig({ retryAttempts: 0 }));
    expect(await adapter.healthCheck()).toBe(false);
  });
});
