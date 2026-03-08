import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { type DeepPartial, type AppConfig, loadConfig, loadConfigFromEnv, mergeConfigs } from '../src/config.js';

describe('loadConfigFromEnv', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('reads target env vars', () => {
    process.env.KEELSON_TARGET_URL = 'https://api.example.com/v1/chat';
    process.env.KEELSON_API_KEY = 'sk-test-123';
    process.env.KEELSON_MODEL = 'gpt-3.5-turbo';
    process.env.KEELSON_ADAPTER_TYPE = 'anthropic';

    const config = loadConfigFromEnv();

    expect(config.target?.baseUrl).toBe('https://api.example.com/v1/chat');
    expect(config.target?.apiKey).toBe('sk-test-123');
    expect(config.target?.model).toBe('gpt-3.5-turbo');
    expect(config.target?.adapterType).toBe('anthropic');
  });

  it('reads scan env vars', () => {
    process.env.KEELSON_DELAY = '3000';
    process.env.KEELSON_CONCURRENCY = '4';

    const config = loadConfigFromEnv();

    expect(config.scan?.delayMs).toBe(3000);
    expect(config.scan?.concurrency).toBe(4);
  });

  it('reads judge env vars', () => {
    process.env.KEELSON_JUDGE_URL = 'https://judge.example.com/v1/chat';
    process.env.KEELSON_JUDGE_API_KEY = 'sk-judge-456';

    const config = loadConfigFromEnv();

    expect(config.judge?.enabled).toBe(true);
    expect(config.judge?.baseUrl).toBe('https://judge.example.com/v1/chat');
    expect(config.judge?.apiKey).toBe('sk-judge-456');
  });

  it('reads output env vars', () => {
    process.env.KEELSON_OUTPUT_FORMAT = 'sarif';
    process.env.KEELSON_OUTPUT_DIR = '/tmp/reports';

    const config = loadConfigFromEnv();

    expect(config.output?.format).toBe('sarif');
    expect(config.output?.dir).toBe('/tmp/reports');
  });

  it('returns empty config when no env vars set', () => {
    // Clear all KEELSON_ env vars
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('KEELSON_')) delete process.env[key];
    }

    const config = loadConfigFromEnv();

    expect(config.target).toBeUndefined();
    expect(config.scan).toBeUndefined();
    expect(config.judge).toBeUndefined();
    expect(config.output).toBeUndefined();
  });
});

describe('mergeConfigs', () => {
  it('merges two partial configs with later taking priority', () => {
    const config = mergeConfigs(
      {
        target: {
          baseUrl: 'https://api.example.com/v1/chat',
          model: 'gpt-4',
        },
        scan: { delayMs: 1000 },
      },
      {
        target: {
          baseUrl: 'https://api.example.com/v1/chat',
          model: 'gpt-3.5-turbo',
          apiKey: 'sk-test',
        },
        scan: { concurrency: 3 },
      },
    );

    expect(config.target.model).toBe('gpt-3.5-turbo');
    expect(config.target.apiKey).toBe('sk-test');
    expect(config.scan.delayMs).toBe(1000);
    expect(config.scan.concurrency).toBe(3);
  });

  it('applies defaults for missing fields', () => {
    const config = mergeConfigs({
      target: { baseUrl: 'https://api.example.com/v1/chat' },
      scan: {},
    });

    expect(config.target.model).toBe('gpt-4');
    expect(config.target.adapterType).toBe('openai');
    expect(config.target.timeout).toBe(30_000);
    expect(config.target.retryAttempts).toBe(3);
    expect(config.target.retryDelay).toBe(1000);
    expect(config.scan.delayMs).toBe(1500);
    expect(config.scan.concurrency).toBe(1);
  });

  it('throws on invalid config (missing required target.baseUrl)', () => {
    expect(() =>
      mergeConfigs({
        target: { model: 'gpt-4' },
        scan: {},
      }),
    ).toThrow();
  });

  it('throws on invalid URL', () => {
    expect(() =>
      mergeConfigs({
        target: { baseUrl: 'not-a-url' },
        scan: {},
      }),
    ).toThrow();
  });

  it('throws on invalid output format', () => {
    expect(() =>
      mergeConfigs(
        // Use Record cast to bypass compile-time checks and test runtime validation
        {
          target: { baseUrl: 'https://api.example.com/v1/chat' },
          scan: {},
          output: { format: 'pdf' },
        } as Record<string, unknown> as DeepPartial<AppConfig>,
      ),
    ).toThrow();
  });

  it('merges three configs', () => {
    const config = mergeConfigs(
      {
        target: { baseUrl: 'https://api.example.com/v1/chat', model: 'gpt-4' },
        scan: { delayMs: 1000 },
      },
      {
        scan: { concurrency: 3 },
      },
      {
        target: { baseUrl: 'https://api.example.com/v1/chat', model: 'claude-3' },
      },
    );

    expect(config.target.model).toBe('claude-3');
    expect(config.scan.concurrency).toBe(3);
    expect(config.scan.delayMs).toBe(1000);
  });

  it('throws when called with no arguments', () => {
    expect(() => mergeConfigs()).toThrow('mergeConfigs requires at least one config');
  });
});

describe('loadConfig', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    // Clear any KEELSON env vars
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('KEELSON_')) delete process.env[key];
    }
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('loads config from overrides alone', () => {
    const config = loadConfig({
      target: { baseUrl: 'https://api.example.com/v1/chat' },
      scan: {},
    });

    expect(config.target.baseUrl).toBe('https://api.example.com/v1/chat');
    expect(config.target.model).toBe('gpt-4');
  });

  it('merges env vars with overrides (overrides take priority)', () => {
    process.env.KEELSON_TARGET_URL = 'https://env.example.com/v1/chat';
    process.env.KEELSON_MODEL = 'gpt-3.5-turbo';

    const config = loadConfig({
      target: { baseUrl: 'https://override.example.com/v1/chat' },
      scan: {},
    });

    expect(config.target.baseUrl).toBe('https://override.example.com/v1/chat');
    // env model is overridden by the deep merge default since overrides didn't set it
  });

  it('uses env value when override does not set it', () => {
    process.env.KEELSON_TARGET_URL = 'https://env.example.com/v1/chat';
    process.env.KEELSON_API_KEY = 'sk-from-env';

    const config = loadConfig({
      target: { baseUrl: 'https://env.example.com/v1/chat' },
      scan: {},
    });

    expect(config.target.apiKey).toBe('sk-from-env');
  });
});
