import nock from 'nock';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { CrewAIAdapter } from '../../src/adapters/crewai.js';
import type { AdapterConfig } from '../../src/types/index.js';

const BASE = 'http://localhost:8001';

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return { type: 'crewai', baseUrl: BASE, ...overrides };
}

describe('CrewAIAdapter', () => {
  beforeEach(() => nock.cleanAll());
  afterEach(() => nock.cleanAll());

  it('sends kickoff request and extracts result', async () => {
    nock(BASE).post('/kickoff').reply(200, { result: 'Crew output here' });

    const adapter = new CrewAIAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'Do the task' }]);
    expect(result.content).toBe('Crew output here');
  });

  it('sends last user message as input', async () => {
    nock(BASE)
      .post('/kickoff', (body: Record<string, unknown>) => body.input === 'second')
      .reply(200, { result: 'ok' });

    const adapter = new CrewAIAdapter(makeConfig());
    await adapter.send([
      { role: 'user', content: 'first' },
      { role: 'assistant', content: 'ack' },
      { role: 'user', content: 'second' },
    ]);
  });

  it('falls back to raw field', async () => {
    nock(BASE).post('/kickoff').reply(200, { raw: 'raw output' });

    const adapter = new CrewAIAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('raw output');
  });

  it('handles empty response', async () => {
    nock(BASE).post('/kickoff').reply(200, {});

    const adapter = new CrewAIAdapter(makeConfig());
    const result = await adapter.send([{ role: 'user', content: 'test' }]);
    expect(result.content).toBe('');
  });

  it('healthCheck returns true on success', async () => {
    nock(BASE).post('/kickoff').reply(200, { result: 'pong' });

    const adapter = new CrewAIAdapter(makeConfig());
    expect(await adapter.healthCheck()).toBe(true);
  });
});
