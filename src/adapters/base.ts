import axios, { type AxiosError, type AxiosInstance } from 'axios';
import pRetry, { AbortError, type RetryContext } from 'p-retry';
import { ProxyAgent } from 'proxy-agent';

import { adapterLogger } from '../core/logger.js';
import type { Adapter, AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

export abstract class BaseAdapter implements Adapter {
  protected client: AxiosInstance;
  protected config: AdapterConfig;

  /** Resolve the effective model name, falling back to the given default. */
  protected resolveModel(defaultModel: string): string {
    const m = this.config.model;
    return m && m !== 'default' ? m : defaultModel;
  }

  /** POST to the given path and return data + latency in ms. */
  protected async timedPost<T = unknown>(path: string, payload: unknown): Promise<{ data: T; latencyMs: number }> {
    const start = performance.now();
    const { data } = await this.client.post<T>(path, payload);
    return { data, latencyMs: Math.round(performance.now() - start) };
  }

  /** Wrap an async operation with p-retry for transient failures. */
  protected async withRetry<T>(fn: () => Promise<T>): Promise<T> {
    const retries = this.config.retryAttempts ?? 3;
    const baseDelay = this.config.retryDelay ?? 1000;

    return pRetry(fn, {
      retries,
      minTimeout: baseDelay,
      onFailedAttempt: async (context: RetryContext) => {
        const axiosError = context.error as AxiosError;
        const status = axiosError.response?.status;
        if (status && !RETRYABLE_STATUS.has(status)) {
          throw new AbortError(context.error.message); // abort on non-retryable status
        }

        // Honor Retry-After header from 429 responses
        const retryAfterHeader = axiosError.response?.headers?.['retry-after'] as string | undefined;
        if (retryAfterHeader) {
          const seconds = Number(retryAfterHeader);
          if (!isNaN(seconds) && seconds > 0) {
            const delayMs = seconds * 1000;
            adapterLogger.debug(
              { attempt: context.attemptNumber, retriesLeft: context.retriesLeft, status, retryAfterMs: delayMs },
              'Honoring Retry-After header',
            );
            await new Promise((resolve) => setTimeout(resolve, delayMs));
            return;
          }
        }

        adapterLogger.debug(
          { attempt: context.attemptNumber, retriesLeft: context.retriesLeft, status },
          'Retrying request',
        );
      },
    });
  }

  constructor(config: AdapterConfig) {
    this.config = config;

    const proxyUrl = process.env.KEELSON_PROXY_URL;
    const hasProxy = proxyUrl || process.env.HTTP_PROXY || process.env.HTTPS_PROXY;

    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout ?? 30_000,
      headers: {
        'Content-Type': 'application/json',
        ...config.headers,
      },
      ...(hasProxy
        ? {
            httpAgent: new ProxyAgent(),
            httpsAgent: new ProxyAgent(),
          }
        : {}),
    });
  }

  abstract send(messages: Turn[]): Promise<AdapterResponse>;

  async healthCheck(): Promise<boolean> {
    try {
      await this.send([{ role: 'user', content: 'ping' }]);
      return true;
    } catch {
      return false;
    }
  }

  resetSession(): void {
    // No-op for stateless adapters. Stateful adapters override.
  }

  async close(): Promise<void> {
    // No-op by default. Adapters with resources override.
  }
}
