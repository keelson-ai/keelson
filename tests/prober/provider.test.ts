import { describe, expect, it } from 'vitest';

import { PROVIDER_ROTATION, detectProvider, selectProberAdapter } from '../../src/prober/provider.js';
import type { AdapterConfig } from '../../src/types/index.js';

describe('detectProvider', () => {
  it('detects OpenAI from URL', () => {
    expect(detectProvider('https://api.openai.com/v1/chat/completions')).toBe('openai');
  });

  it('detects Anthropic from URL', () => {
    expect(detectProvider('https://api.anthropic.com/v1/messages')).toBe('anthropic');
  });

  it('detects Google from googleapis.com', () => {
    expect(detectProvider('https://generativelanguage.googleapis.com/v1')).toBe('google');
  });

  it('detects Google from google.com', () => {
    expect(detectProvider('https://ai.google.com/api')).toBe('google');
  });

  it('detects Azure from URL', () => {
    expect(detectProvider('https://myinstance.openai.azure.com/deployments')).toBe('azure');
  });

  it('returns custom for unknown URLs', () => {
    expect(detectProvider('https://my-custom-llm.example.com/api')).toBe('custom');
  });

  it('is case insensitive', () => {
    expect(detectProvider('https://API.OPENAI.COM/v1')).toBe('openai');
  });
});

describe('PROVIDER_ROTATION', () => {
  it('maps openai to anthropic', () => {
    expect(PROVIDER_ROTATION['openai']).toBe('anthropic');
  });

  it('maps anthropic to openai', () => {
    expect(PROVIDER_ROTATION['anthropic']).toBe('openai');
  });

  it('maps google to anthropic', () => {
    expect(PROVIDER_ROTATION['google']).toBe('anthropic');
  });

  it('maps azure to anthropic', () => {
    expect(PROVIDER_ROTATION['azure']).toBe('anthropic');
  });

  it('maps custom to openai', () => {
    expect(PROVIDER_ROTATION['custom']).toBe('openai');
  });
});

describe('selectProberAdapter', () => {
  it('swaps OpenAI target to Anthropic prober', () => {
    const targetConfig: AdapterConfig = {
      type: 'openai',
      baseUrl: 'https://api.openai.com/v1',
      apiKey: 'sk-test',
      model: 'gpt-4',
    };
    const proberConfig = selectProberAdapter(targetConfig);

    expect(proberConfig.type).toBe('anthropic');
    expect(proberConfig.baseUrl).toBe('https://api.anthropic.com');
  });

  it('swaps Anthropic target to OpenAI prober', () => {
    const targetConfig: AdapterConfig = {
      type: 'anthropic',
      baseUrl: 'https://api.anthropic.com/v1',
      apiKey: 'sk-ant-test',
    };
    const proberConfig = selectProberAdapter(targetConfig);

    expect(proberConfig.type).toBe('openai');
    expect(proberConfig.baseUrl).toBe('https://api.openai.com');
  });

  it('preserves other config fields', () => {
    const targetConfig: AdapterConfig = {
      type: 'openai',
      baseUrl: 'https://api.openai.com/v1',
      apiKey: 'sk-test',
      model: 'gpt-4',
      timeout: 60000,
    };
    const proberConfig = selectProberAdapter(targetConfig);

    expect(proberConfig.apiKey).toBe('sk-test');
    expect(proberConfig.model).toBe('gpt-4');
    expect(proberConfig.timeout).toBe(60000);
  });

  it('returns same config for unknown provider with no rotation', () => {
    const targetConfig: AdapterConfig = {
      type: 'custom',
      baseUrl: 'https://my-custom-llm.example.com/api',
      apiKey: 'key-123',
    };
    const proberConfig = selectProberAdapter(targetConfig);

    // custom maps to openai
    expect(proberConfig.type).toBe('openai');
    expect(proberConfig.baseUrl).toBe('https://api.openai.com');
  });
});
