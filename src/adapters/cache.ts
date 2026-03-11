import crypto from 'node:crypto';

import { LRUCache } from 'lru-cache';

import type { Adapter, AdapterResponse, Turn } from '../types/index.js';

export interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  size: number;
}

/**
 * Composable caching wrapper for any Adapter.
 * Uses SHA-256 hash of messages as cache key with LRU eviction and TTL.
 */
export class CachingAdapter implements Adapter {
  private readonly inner: Adapter;
  private readonly cache: LRUCache<string, AdapterResponse>;
  private _hits = 0;
  private _misses = 0;
  private _evictions = 0;

  constructor(adapter: Adapter, maxEntries = 10_000, ttlSeconds = 3600) {
    this.inner = adapter;
    this.cache = new LRUCache<string, AdapterResponse>({
      max: maxEntries,
      ttl: ttlSeconds * 1000,
      dispose: () => {
        this._evictions++;
      },
    });
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

  async send(messages: Turn[]): Promise<AdapterResponse> {
    const key = this.cacheKey(messages);
    const cached = this.cache.get(key);

    if (cached) {
      this._hits++;
      return { ...cached };
    }

    this._misses++;
    const response = await this.inner.send(messages);
    this.cache.set(key, { ...response });
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
