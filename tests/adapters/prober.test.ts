import { describe, expect, it, vi } from 'vitest';

import { ProberAdapter } from '../../src/adapters/prober.js';
import type { Adapter, AdapterResponse, Turn } from '../../src/types/index.js';

function createMockAdapter(): Adapter & { lastMessages?: Turn[] } {
  const adapter: Adapter & { lastMessages?: Turn[] } = {
    send: vi.fn().mockImplementation(async (messages: Turn[]) => {
      adapter.lastMessages = messages;
      return { content: 'generated probe', raw: {}, latencyMs: 50 } as AdapterResponse;
    }),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  };
  return adapter;
}

describe('ProberAdapter', () => {
  it('prepends default system prompt', async () => {
    const inner = createMockAdapter();
    const prober = new ProberAdapter(inner);

    await prober.send([{ role: 'user', content: 'Generate a probe' }]);

    const msgs = inner.lastMessages as Turn[];
    expect(msgs).toHaveLength(2);
    expect(msgs[0].role).toBe('system');
    expect(msgs[0].content).toContain('security researcher');
    expect(msgs[1].role).toBe('user');
  });

  it('uses custom system prompt', async () => {
    const inner = createMockAdapter();
    const prober = new ProberAdapter(inner, 'Custom system prompt');

    await prober.send([{ role: 'user', content: 'test' }]);

    const msgs = inner.lastMessages as Turn[];
    expect(msgs[0].content).toBe('Custom system prompt');
  });

  it('preserves all original messages', async () => {
    const inner = createMockAdapter();
    const prober = new ProberAdapter(inner);

    const messages: Turn[] = [
      { role: 'user', content: 'msg1' },
      { role: 'assistant', content: 'resp1' },
      { role: 'user', content: 'msg2' },
    ];

    await prober.send(messages);

    // System prompt + 3 original messages
    const msgs = inner.lastMessages as Turn[];
    expect(msgs).toHaveLength(4);
    expect(msgs[1]).toEqual(messages[0]);
    expect(msgs[2]).toEqual(messages[1]);
    expect(msgs[3]).toEqual(messages[2]);
  });

  it('returns inner adapter response', async () => {
    const inner = createMockAdapter();
    const prober = new ProberAdapter(inner);

    const result = await prober.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('generated probe');
    expect(result.latencyMs).toBe(50);
  });

  it('delegates healthCheck', async () => {
    const inner = createMockAdapter();
    const prober = new ProberAdapter(inner);

    expect(await prober.healthCheck()).toBe(true);
    expect(inner.healthCheck).toHaveBeenCalled();
  });

  it('delegates resetSession', () => {
    const inner = createMockAdapter();
    const prober = new ProberAdapter(inner);

    prober.resetSession();
    expect(inner.resetSession).toHaveBeenCalled();
  });

  it('delegates close', async () => {
    const inner = createMockAdapter();
    const prober = new ProberAdapter(inner);

    await prober.close();
    expect(inner.close).toHaveBeenCalled();
  });
});
