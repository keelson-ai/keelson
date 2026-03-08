import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { LangChainAdapter } from '../../src/adapters/langchain.js';
import type { AdapterConfig } from '../../src/types/index.js';

const BASE = 'http://localhost:8002';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'langchain', baseUrl: BASE, ...overrides };
}

describe('LangChainAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('sends invoke request and extracts output', async () => {
    nock(BASE).post('/invoke').reply(200, { output: 'Chain result' });

    const adapter = new LangChainAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'Run chain' }]);
    expect(result.content).toBe('Chain result');
  });

  it('uses custom input/output keys', async () => {
    nock(BASE)
      .post('/invoke', (body: Record<string, unknown>) => body.query === 'test query')
      .reply(200, { answer: 'Custom answer' });

    const adapter = new LangChainAdapter(makeConfig({ inputKey: 'query', outputKey: 'answer' }));
    const result = await adapter.send([{ role: 'user', content: 'test query' }]);
    expect(result.content).toBe('Custom answer');
  });

  it('handles string response', async () => {
    nock(BASE).post('/invoke').reply(200, '"plain string"', { 'Content-Type': 'application/json' });

    const adapter = new LangChainAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('plain string');
  });

  it('falls back to content field', async () => {
    nock(BASE).post('/invoke').reply(200, { content: 'fallback content' });

    const adapter = new LangChainAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('fallback content');
  });

  it('sends last user message as input', async () => {
    nock(BASE)
      .post('/invoke', (body: Record<string, unknown>) => body.input === 'last msg')
      .reply(200, { output: 'ok' });

    const adapter = new LangChainAdapter(makeConfig());
    await adapter.send([
      { role: 'user', content: 'first' },
      { role: 'user', content: 'last msg' },
    ]);
  });

  it('healthCheck returns true on success', async () => {
    nock(BASE).post('/invoke').reply(200, { output: 'pong' });

    const adapter = new LangChainAdapter(makeConfig());
    expect(await adapter.healthCheck()).toBe(true);
  });
});
