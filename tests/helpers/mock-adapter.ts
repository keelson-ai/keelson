import { vi } from 'vitest';

import type { Adapter, AdapterResponse } from '../../src/types/index.js';

/**
 * Creates a mock adapter that returns responses in sequence.
 * If responses run out, repeats the last one.
 */
export function mockAdapter(responses: string | string[] = 'PWNED'): Adapter {
  const list = Array.isArray(responses) ? responses : [responses];
  let callIndex = 0;
  return {
    send: vi.fn().mockImplementation(async (): Promise<AdapterResponse> => {
      const content = list[callIndex] ?? list[list.length - 1];
      callIndex++;
      return { content, raw: {}, latencyMs: 50 };
    }),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  };
}
