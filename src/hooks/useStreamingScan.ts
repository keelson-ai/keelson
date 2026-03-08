import { useCallback, useEffect, useRef, useState } from 'react';

import { scan } from '../core/scanner.js';
import type { ScanOptions } from '../core/scanner.js';
import type { Adapter, Finding, ScanResult } from '../types/index.js';
import { Verdict } from '../types/index.js';

export interface StreamingScanState {
  status: 'idle' | 'running' | 'complete' | 'error';
  current: number;
  total: number;
  currentProbe?: string;
  findings: Finding[];
  verdictCounts: { vulnerable: number; safe: number; inconclusive: number };
  result?: ScanResult;
  error?: string;
}

export interface UseStreamingScanResult extends StreamingScanState {
  start: () => void;
  abort: () => void;
}

const INITIAL_COUNTS = { vulnerable: 0, safe: 0, inconclusive: 0 };

export function useStreamingScan(
  target: string,
  adapter: Adapter,
  options: Omit<ScanOptions, 'onFinding'> = {},
): UseStreamingScanResult {
  const [state, setState] = useState<StreamingScanState>({
    status: 'idle',
    current: 0,
    total: 0,
    findings: [],
    verdictCounts: { ...INITIAL_COUNTS },
  });

  const runningRef = useRef(false);
  const abortedRef = useRef(false);
  const mountedRef = useRef(true);

  // Track mount status to prevent setState on unmounted component
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const abort = useCallback(() => {
    abortedRef.current = true;
  }, []);

  const start = useCallback(() => {
    if (runningRef.current) return;
    runningRef.current = true;
    abortedRef.current = false;

    setState({
      status: 'running',
      current: 0,
      total: 0,
      findings: [],
      verdictCounts: { ...INITIAL_COUNTS },
      result: undefined,
      error: undefined,
    });

    const scanOptions: ScanOptions = {
      ...options,
      onFinding: (finding: Finding, current: number, total: number) => {
        if (!mountedRef.current || abortedRef.current) return;

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
        runningRef.current = false;
        if (!mountedRef.current || abortedRef.current) return;
        setState((prev) => ({
          ...prev,
          status: 'complete',
          result,
          currentProbe: undefined,
        }));
      })
      .catch((err: unknown) => {
        runningRef.current = false;
        if (!mountedRef.current || abortedRef.current) return;
        setState((prev) => ({
          ...prev,
          status: 'error',
          error: err instanceof Error ? err.message : String(err),
        }));
      });
  }, [target, adapter, options]);

  return { ...state, start, abort };
}
