import { useCallback, useState } from 'react';

import { scan } from '../core/scanner.js';
import type { ScanOptions } from '../core/scanner.js';
import type { Adapter, Finding, ScanResult } from '../types/index.js';
import { Verdict } from '../types/index.js';

export interface ScanState {
  status: 'idle' | 'running' | 'complete' | 'error';
  current: number;
  total: number;
  currentProbe?: string;
  findings: Finding[];
  verdictCounts: { vulnerable: number; safe: number; inconclusive: number };
  result?: ScanResult;
  error?: string;
}

export interface UseScanResult extends ScanState {
  start: () => void;
}

export function useScan(
  target: string,
  adapter: Adapter,
  options: Omit<ScanOptions, 'onFinding'> = {},
): UseScanResult {
  const [state, setState] = useState<ScanState>({
    status: 'idle',
    current: 0,
    total: 0,
    findings: [],
    verdictCounts: { vulnerable: 0, safe: 0, inconclusive: 0 },
  });

  const start = useCallback(() => {
    if (state.status === 'running') return;

    setState((prev) => ({
      ...prev,
      status: 'running',
      current: 0,
      total: 0,
      findings: [],
      verdictCounts: { vulnerable: 0, safe: 0, inconclusive: 0 },
      result: undefined,
      error: undefined,
    }));

    const scanOptions: ScanOptions = {
      ...options,
      onFinding: (finding: Finding, current: number, total: number) => {
        setState((prev) => {
          const newCounts = { ...prev.verdictCounts };
          if (finding.verdict === Verdict.Vulnerable) newCounts.vulnerable++;
          else if (finding.verdict === Verdict.Safe) newCounts.safe++;
          else newCounts.inconclusive++;

          return {
            ...prev,
            current,
            total,
            currentProbe: `${finding.probeId}: ${finding.probeName}`,
            findings: [...prev.findings, finding],
            verdictCounts: newCounts,
          };
        });
      },
    };

    scan(target, adapter, scanOptions)
      .then((result) => {
        setState((prev) => ({
          ...prev,
          status: 'complete',
          result,
          currentProbe: undefined,
        }));
      })
      .catch((err: unknown) => {
        setState((prev) => ({
          ...prev,
          status: 'error',
          error: err instanceof Error ? err.message : String(err),
        }));
      });
  }, [target, adapter, options, state.status]);

  return { ...state, start };
}
