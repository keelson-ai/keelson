// tests/cli/verbosity.test.ts
import { describe, expect, it } from 'vitest';

import { Verbosity, parseVerbosity } from '../../src/cli/verbosity.js';

describe('parseVerbosity', () => {
  it('returns Silent when no flags', () => {
    expect(parseVerbosity(undefined)).toBe(Verbosity.Silent);
  });

  it('counts boolean -v as level 1', () => {
    expect(parseVerbosity(true)).toBe(Verbosity.Verdicts);
  });

  it('counts repeated -v flags', () => {
    expect(parseVerbosity(1)).toBe(Verbosity.Verdicts);
    expect(parseVerbosity(2)).toBe(Verbosity.Conversations);
    expect(parseVerbosity(3)).toBe(Verbosity.Detection);
    expect(parseVerbosity(4)).toBe(Verbosity.Debug);
  });

  it('clamps to max level 4', () => {
    expect(parseVerbosity(7)).toBe(Verbosity.Debug);
  });
});
