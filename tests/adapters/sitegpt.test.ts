import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SiteGPTAdapter } from '../../src/adapters/sitegpt.js';
import type { AdapterConfig } from '../../src/types/index.js';

const API_BASE = 'https://sitegpt.ai/api/v0';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'sitegpt', baseUrl: API_BASE, apiKey: 'sgpt-key', chatbotId: 'bot-123', ...overrides };
}

describe('SiteGPTAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('throws if chatbotId is missing', () => {
    expect(() => new SiteGPTAdapter({ type: 'sitegpt', baseUrl: API_BASE, apiKey: 'key' })).toThrow('chatbotId');
  });

  describe('API mode (with apiKey)', () => {
    it('sends message and extracts response', async () => {
      nock(API_BASE)
        .post('/chatbots/bot-123/message')
        .reply(200, {
          data: {
            message: { answer: { text: 'SiteGPT says hello' } },
            threadId: 'thread-abc',
          },
        });

      const adapter = new SiteGPTAdapter(makeConfig());
      const result = await adapter.send([{ role: 'user', content: 'Hi there' }]);

      expect(result.content).toBe('SiteGPT says hello');
      expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    });

    it('sends Bearer auth header', async () => {
      nock(API_BASE)
        .post('/chatbots/bot-123/message')
        .matchHeader('Authorization', 'Bearer sgpt-key')
        .reply(200, { data: { message: { answer: { text: 'ok' } } } });

      const adapter = new SiteGPTAdapter(makeConfig());
      await adapter.send([{ role: 'user', content: 'test' }]);
    });

    it('includes threadId after first message', async () => {
      nock(API_BASE)
        .post('/chatbots/bot-123/message')
        .reply(200, {
          data: {
            message: { answer: { text: 'first' } },
            threadId: 'thread-xyz',
          },
        });

      nock(API_BASE)
        .post('/chatbots/bot-123/message', (body: Record<string, unknown>) => body.threadId === 'thread-xyz')
        .reply(200, {
          data: { message: { answer: { text: 'second' } } },
        });

      const adapter = new SiteGPTAdapter(makeConfig());
      await adapter.send([{ role: 'user', content: 'msg1' }]);
      const result = await adapter.send([{ role: 'user', content: 'msg2' }]);
      expect(result.content).toBe('second');
    });

    it('extracts last user message', async () => {
      nock(API_BASE)
        .post('/chatbots/bot-123/message', (body: Record<string, unknown>) => body.message === 'latest')
        .reply(200, { data: { message: { answer: { text: 'ok' } } } });

      const adapter = new SiteGPTAdapter(makeConfig());
      await adapter.send([
        { role: 'user', content: 'old' },
        { role: 'assistant', content: 'response' },
        { role: 'user', content: 'latest' },
      ]);
    });

    it('handles missing answer text gracefully', async () => {
      nock(API_BASE)
        .post('/chatbots/bot-123/message')
        .reply(200, { data: { message: {} } });

      const adapter = new SiteGPTAdapter(makeConfig());
      const result = await adapter.send([{ role: 'user', content: 'test' }]);
      expect(result.content).toBe('');
    });

    it('resetSession clears thread', async () => {
      nock(API_BASE)
        .post('/chatbots/bot-123/message')
        .reply(200, {
          data: { message: { answer: { text: 'ok' } }, threadId: 'thread-1' },
        });

      // After reset, no threadId should be sent
      nock(API_BASE)
        .post('/chatbots/bot-123/message', (body: Record<string, unknown>) => !body.threadId)
        .reply(200, { data: { message: { answer: { text: 'fresh' } } } });

      const adapter = new SiteGPTAdapter(makeConfig());
      await adapter.send([{ role: 'user', content: 'msg1' }]);
      adapter.resetSession();
      const result = await adapter.send([{ role: 'user', content: 'msg2' }]);
      expect(result.content).toBe('fresh');
    });
  });
});
