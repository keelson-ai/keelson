import { describe, expect, it } from 'vitest';

import { checkFailGates } from '../../src/cli/utils.js';
import { Logger, Verbosity } from '../../src/cli/verbosity.js';

const logger = new Logger(Verbosity.Silent);

describe('checkFailGates', () => {
  it('returns 0 when failOnVuln is false', () => {
    expect(checkFailGates(5, 10, false, 0, logger)).toBe(0);
  });

  it('returns 0 when there are no findings', () => {
    expect(checkFailGates(0, 0, true, 0, logger)).toBe(0);
  });

  it('returns 1 when vuln rate exceeds threshold', () => {
    // 3 out of 10 = 30%, threshold at 20%
    expect(checkFailGates(3, 10, true, 0.2, logger)).toBe(1);
  });

  it('returns 0 when vuln rate equals threshold', () => {
    // 2 out of 10 = 20%, threshold at 20% — not exceeded, so pass
    expect(checkFailGates(2, 10, true, 0.2, logger)).toBe(0);
  });

  it('returns 0 when vuln rate is below threshold', () => {
    // 1 out of 10 = 10%, threshold at 20%
    expect(checkFailGates(1, 10, true, 0.2, logger)).toBe(0);
  });

  it('returns 1 with zero threshold and any vulnerability', () => {
    // 1 out of 10 = 10%, threshold at 0% — exceeded
    expect(checkFailGates(1, 10, true, 0, logger)).toBe(1);
  });

  it('returns 0 with zero threshold and no vulnerabilities', () => {
    expect(checkFailGates(0, 10, true, 0, logger)).toBe(0);
  });

  it('returns 1 when all probes are vulnerable and threshold is 0.9', () => {
    // 10 out of 10 = 100%, threshold at 90%
    expect(checkFailGates(10, 10, true, 0.9, logger)).toBe(1);
  });
});
