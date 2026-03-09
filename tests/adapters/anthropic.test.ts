import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AnthropicAdapter } from '../../src/adapters/anthropic.js';
import type { AdapterConfig } from '../../src/types/index.js';

const BASE_URL = 'https://api.anthropic.com/v1/messages';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'anthropic', baseUrl: BASE_URL, apiKey: 'sk-ant-test', ...overrides };
}

describe('AnthropicAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('sends messages and parses content blocks', async () => {
    nock(BASE_URL)
      .post('')
      .reply(200, {
        content: [{ type: 'text', text: 'Hello from Claude!' }],
      });

    const adapter = new AnthropicAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'Hi' }]);
    expect(result.content).toBe('Hello from Claude!');
  });

  it('sends x-api-key and anthropic-version headers', async () => {
    nock(BASE_URL)
      .post('')
      .matchHeader('x-api-key', 'sk-ant-test')
      .matchHeader('anthropic-version', '2023-06-01')
      .reply(200, { content: [{ type: 'text', text: 'ok' }] });

    const adapter = new AnthropicAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('extracts system messages to top-level parameter', async () => {
    nock(BASE_URL)
      .post('', (body: Record<string, unknown>) => {
        const msgs = body.messages as Array<{ role: string }>;
        return body.system === 'Be helpful.' && msgs.length === 1 && msgs[0].role === 'user';
      })
      .reply(200, { content: [{ type: 'text', text: 'ok' }] });

    const adapter = new AnthropicAdapter(makeConfig());
    await adapter.send([
      { role: 'system', content: 'Be helpful.' },
      { role: 'user', content: 'Hi' },
    ]);
  });

  it('joins multiple system messages', async () => {
    nock(BASE_URL)
      .post('', (body: Record<string, unknown>) => {
        return body.system === 'Rule 1.\n\nRule 2.';
      })
      .reply(200, { content: [{ type: 'text', text: 'ok' }] });

    const adapter = new AnthropicAdapter(makeConfig());
    await adapter.send([
      { role: 'system', content: 'Rule 1.' },
      { role: 'system', content: 'Rule 2.' },
      { role: 'user', content: 'Hi' },
    ]);
  });

  it('uses claude-sonnet-4-6 as default model', async () => {
    nock(BASE_URL)
      .post('', (body: Record<string, unknown>) => body.model === 'claude-sonnet-4-6')
      .reply(200, { content: [{ type: 'text', text: 'ok' }] });

    const adapter = new AnthropicAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('uses custom model', async () => {
    nock(BASE_URL)
      .post('', (body: Record<string, unknown>) => body.model === 'claude-opus-4-6')
      .reply(200, { content: [{ type: 'text', text: 'ok' }] });

    const adapter = new AnthropicAdapter(makeConfig({ model: 'claude-opus-4-6' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('concatenates multiple text blocks', async () => {
    nock(BASE_URL)
      .post('')
      .reply(200, {
        content: [
          { type: 'text', text: 'Part 1. ' },
          { type: 'tool_use', id: 'x' },
          { type: 'text', text: 'Part 2.' },
        ],
      });

    const adapter = new AnthropicAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('Part 1. Part 2.');
  });

  it('handles empty content array', async () => {
    nock(BASE_URL).post('').reply(200, { content: [] });

    const adapter = new AnthropicAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('');
  });

  it('includes max_tokens in payload', async () => {
    nock(BASE_URL)
      .post('', (body: Record<string, unknown>) => body.max_tokens === 4096)
      .reply(200, { content: [{ type: 'text', text: 'ok' }] });

    const adapter = new AnthropicAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'test' }]);
  });
});
