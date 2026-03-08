import axios, { type AxiosError, type AxiosInstance, type InternalAxiosRequestConfig } from 'axios';

import type { Adapter, AdapterConfig, AdapterResponse, Turn } from '../types/index.js';

const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

interface RetryableConfig extends InternalAxiosRequestConfig {
  __retryCount?: number;
}

export abstract class BaseAdapter implements Adapter {
  protected client: AxiosInstance;
  protected config: AdapterConfig;

  constructor(config: AdapterConfig) {
    this.config = config;
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout ?? 30_000,
      headers: {
        'Content-Type': 'application/json',
        ...config.headers,
      },
    });

    this.setupRetryInterceptor();
  }

  private setupRetryInterceptor(): void {
    const maxRetries = this.config.retryAttempts ?? 3;
    const baseDelay = this.config.retryDelay ?? 1000;

    this.client.interceptors.response.use(undefined, async (error: AxiosError) => {
      const config = error.config as RetryableConfig | undefined;
      if (!config) throw error;

      const attempt = config.__retryCount ?? 0;

      if (attempt >= maxRetries || !error.response || !RETRYABLE_STATUS.has(error.response.status)) {
        throw error;
      }

      config.__retryCount = attempt + 1;

      const retryAfter = error.response.headers['retry-after'];
      const delay =
        typeof retryAfter === 'string' && /^\d+$/.test(retryAfter)
          ? parseInt(retryAfter, 10) * 1000
          : baseDelay * Math.pow(2, attempt);

      await new Promise((r) => setTimeout(r, delay));
      return this.client.request(config);
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
}
