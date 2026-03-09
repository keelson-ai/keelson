import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { LangGraphAdapter } from '../../src/adapters/langgraph.js';
import type { AdapterConfig } from '../../src/types/index.js';

const BASE = 'https://langgraph.example.com';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'langgraph', baseUrl: BASE, apiKey: 'lg-key', ...overrides };
}

describe('LangGraphAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('creates thread and sends run', async () => {
    nock(BASE).post('/threads').reply(200, { thread_id: 'thread-123' });

    nock(BASE)
      .post('/threads/thread-123/runs/wait')
      .reply(200, {
        messages: [{ type: 'ai', content: 'Hello from LangGraph!' }],
      });

    const adapter = new LangGraphAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'Hi' }]);

    expect(result.content).toBe('Hello from LangGraph!');
  });

  it('reuses thread on subsequent calls', async () => {
    nock(BASE).post('/threads').once().reply(200, { thread_id: 'thread-456' });

    nock(BASE)
      .post('/threads/thread-456/runs/wait')
      .twice()
      .reply(200, { messages: [{ type: 'ai', content: 'ok' }] });

    const adapter = new LangGraphAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'msg1' }]);
    await adapter.send([{ role: 'user', content: 'msg2' }]);
  });

  it('resets session and creates new thread', async () => {
    nock(BASE).post('/threads').twice().reply(200, { thread_id: 'thread-new' });

    nock(BASE)
      .post(/\/threads\/thread-new\/runs\/wait/)
      .twice()
      .reply(200, { messages: [{ type: 'ai', content: 'ok' }] });

    const adapter = new LangGraphAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'msg1' }]);
    adapter.resetSession();
    await adapter.send([{ role: 'user', content: 'msg2' }]);
  });

  it('uses custom assistant_id', async () => {
    nock(BASE).post('/threads').reply(200, { thread_id: 'tid' });

    nock(BASE)
      .post('/threads/tid/runs/wait', (body: Record<string, unknown>) => body.assistant_id === 'my-agent')
      .reply(200, { messages: [{ type: 'ai', content: 'ok' }] });

    const adapter = new LangGraphAdapter(makeConfig({ assistantId: 'my-agent' }));
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('extracts content from output.messages', async () => {
    nock(BASE).post('/threads').reply(200, { thread_id: 'tid' });

    nock(BASE)
      .post('/threads/tid/runs/wait')
      .reply(200, {
        output: {
          messages: [{ role: 'assistant', content: 'From output!' }],
        },
      });

    const adapter = new LangGraphAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('From output!');
  });

  it('extracts content from content block array', async () => {
    nock(BASE).post('/threads').reply(200, { thread_id: 'tid' });

    nock(BASE)
      .post('/threads/tid/runs/wait')
      .reply(200, {
        messages: [{ type: 'ai', content: [{ type: 'text', text: 'Block content' }] }],
      });

    const adapter = new LangGraphAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('Block content');
  });

  it('sends x-api-key header', async () => {
    nock(BASE).post('/threads').matchHeader('x-api-key', 'lg-key').reply(200, { thread_id: 'tid' });

    nock(BASE)
      .post('/threads/tid/runs/wait')
      .reply(200, { messages: [{ type: 'ai', content: 'ok' }] });

    const adapter = new LangGraphAdapter(makeConfig());
    await adapter.send([{ role: 'user', content: 'test' }]);
  });

  it('returns empty string when no AI messages', async () => {
    nock(BASE).post('/threads').reply(200, { thread_id: 'tid' });
    nock(BASE)
      .post('/threads/tid/runs/wait')
      .reply(200, { messages: [{ type: 'human', content: 'user msg' }] });

    const adapter = new LangGraphAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('');
  });
});
