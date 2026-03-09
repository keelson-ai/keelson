import crypto from 'node:crypto';

import type { Adapter, AdapterResponse, Turn } from '../types/index.js';

interface CacheEntry {
  response: AdapterResponse;
  createdAt: number;
  hitCount: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  size: number;
}

/**
 * Composable caching wrapper for any Adapter.
 * Uses SHA-256 hash of messages as cache key with TTL + LRU eviction.
 */
export class CachingAdapter implements Adapter {
  private readonly inner: Adapter;
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly cache = new Map<string, CacheEntry>();
  private _hits = 0;
  private _misses = 0;
  private _evictions = 0;

  constructor(adapter: Adapter, maxEntries = 10_000, ttlSeconds = 3600) {
    this.inner = adapter;
    this.maxEntries = maxEntries;
    this.ttlMs = ttlSeconds * 1000;
  }

  get stats(): CacheStats {
    return {
      hits: this._hits,
      misses: this._misses,
      evictions: this._evictions,
      size: this.cache.size,
    };
  }

  private cacheKey(messages: Turn[]): string {
    const payload = JSON.stringify(messages);
    return crypto.createHash('sha256').update(payload).digest('hex');
  }

  private evictExpired(): void {
    const now = performance.now();
    for (const [key, entry] of this.cache) {
      if (now - entry.createdAt > this.ttlMs) {
        this.cache.delete(key);
        this._evictions++;
      }
    }
  }

  private evictLru(): void {
    while (this.cache.size >= this.maxEntries) {
      // Map iterates in insertion order; first key is oldest
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
        this._evictions++;
      }
    }
  }

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const key = this.cacheKey(messages);
    const cached = this.cache.get(key);

    if (cached && performance.now() - cached.createdAt <= this.ttlMs) {
      this._hits++;
      cached.hitCount++;
      return { ...cached.response };
    }

    // Cache miss or expired
    if (cached) {
      this.cache.delete(key);
      this._evictions++;
    }

    this._misses++;
    const response = await this.inner.send(messages);

    this.evictExpired();
    this.evictLru();

    this.cache.set(key, {
      response: { ...response },
      createdAt: performance.now(),
      hitCount: 0,
    });

    return response;
  }

  async healthCheck(): Promise<boolean> {
    return this.inner.healthCheck();
  }

  resetSession(): void {
    this.inner.resetSession?.();
  }

  async close(): Promise<void> {
    await this.inner.close?.();
  }

  clear(): void {
    this.cache.clear();
    this._hits = 0;
    this._misses = 0;
    this._evictions = 0;
  }
}
