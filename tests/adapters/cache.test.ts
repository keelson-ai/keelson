import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CachingAdapter } from '../../src/adapters/cache.js';
import type { Adapter, AdapterResponse, Turn } from '../../src/types/index.js';

function createMockAdapter(response: AdapterResponse): Adapter {
  return {
    send: vi.fn().mockResolvedValue(response),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  };
}

const RESPONSE: AdapterResponse = { content: 'cached response', raw: {}, latencyMs: 100 };

describe('CachingAdapter', () => {
  let mockAdapter: Adapter;
  let cache: CachingAdapter;

  beforeEach(() => {
    mockAdapter = createMockAdapter(RESPONSE);
    cache = new CachingAdapter(mockAdapter);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('forwards first call to inner adapter', async () => {
    const result = await cache.send([{ role: 'user', content: 'hello' }]);
    expect(result.content).toBe('cached response');
    expect(mockAdapter.send).toHaveBeenCalledTimes(1);
  });

  it('returns cached response on second identical call', async () => {
    const messages: Turn[] = [{ role: 'user', content: 'hello' }];

    await cache.send(messages);
    await cache.send(messages);

    expect(mockAdapter.send).toHaveBeenCalledTimes(1);
    expect(cache.stats.hits).toBe(1);
    expect(cache.stats.misses).toBe(1);
  });

  it('treats different messages as different cache keys', async () => {
    await cache.send([{ role: 'user', content: 'msg1' }]);
    await cache.send([{ role: 'user', content: 'msg2' }]);

    expect(mockAdapter.send).toHaveBeenCalledTimes(2);
    expect(cache.stats.misses).toBe(2);
  });

  it('evicts expired entries', async () => {
    // TTL of 0.001 seconds (1ms) = near-instant expiry
    cache = new CachingAdapter(mockAdapter, 10_000, 0.001);

    await cache.send([{ role: 'user', content: 'hello' }]);

    // Wait a tick for the entry to expire
    await new Promise((r) => setTimeout(r, 10));

    await cache.send([{ role: 'user', content: 'hello' }]);

    expect(mockAdapter.send).toHaveBeenCalledTimes(2);
    expect(cache.stats.evictions).toBeGreaterThan(0);
  });

  it('evicts LRU when max entries exceeded', async () => {
    cache = new CachingAdapter(mockAdapter, 2);

    await cache.send([{ role: 'user', content: 'msg1' }]);
    await cache.send([{ role: 'user', content: 'msg2' }]);
    await cache.send([{ role: 'user', content: 'msg3' }]);

    expect(cache.stats.size).toBeLessThanOrEqual(2);
    expect(cache.stats.evictions).toBeGreaterThan(0);
  });

  it('clear resets the entire cache', async () => {
    await cache.send([{ role: 'user', content: 'hello' }]);
    expect(cache.stats.size).toBe(1);

    cache.clear();
    expect(cache.stats.size).toBe(0);
    expect(cache.stats.hits).toBe(0);
    expect(cache.stats.misses).toBe(0);
  });

  it('delegates healthCheck to inner adapter', async () => {
    expect(await cache.healthCheck()).toBe(true);
    expect(mockAdapter.healthCheck).toHaveBeenCalled();
  });

  it('delegates resetSession to inner adapter', () => {
    cache.resetSession();
    expect(mockAdapter.resetSession).toHaveBeenCalled();
  });

  it('delegates close to inner adapter', async () => {
    await cache.close();
    expect(mockAdapter.close).toHaveBeenCalled();
  });

  it('returns copies to prevent mutation', async () => {
    const messages: Turn[] = [{ role: 'user', content: 'hello' }];

    const result1 = await cache.send(messages);
    const result2 = await cache.send(messages);

    // Different object references
    expect(result1).not.toBe(result2);
    expect(result1.content).toBe(result2.content);
  });
});
