import { useCallback, useEffect, useRef, useState } from 'react';

import { executeProbe } from '../core/engine.js';
import type { ExecuteProbeOptions } from '../core/engine.js';
import type { Adapter, Finding, ProbeTemplate } from '../types/index.js';

export interface ProbeState {
  status: 'idle' | 'running' | 'complete' | 'error';
  finding?: Finding;
  currentStep?: number;
  error?: string;
}

export interface UseEngineResult extends ProbeState {
  run: () => void;
  abort: () => void;
}

const DEFAULT_OPTIONS: Omit<ExecuteProbeOptions, 'onTurn'> = {};

export function useEngine(
  template: ProbeTemplate,
  adapter: Adapter,
  options: Omit<ExecuteProbeOptions, 'onTurn'> = DEFAULT_OPTIONS,
): UseEngineResult {
  const [state, setState] = useState<ProbeState>({ status: 'idle' });
  const mountedRef = useRef(true);
  const abortedRef = useRef(false);
  const runningRef = useRef(false);

  const abort = useCallback(() => {
    abortedRef.current = true;
  }, []);

  const run = useCallback(() => {
    if (runningRef.current) return;
    runningRef.current = true;
    abortedRef.current = false;

    setState({ status: 'running' });

    const probeOptions: ExecuteProbeOptions = {
      ...options,
      onTurn: (stepIndex: number) => {
        if (abortedRef.current) return;
        setState((prev) => ({ ...prev, currentStep: stepIndex }));
      },
    };

    executeProbe(template, adapter, probeOptions)
      .then((finding) => {
        runningRef.current = false;
        if (abortedRef.current || !mountedRef.current) return;
        setState({ status: 'complete', finding });
      })
      .catch((err: unknown) => {
        runningRef.current = false;
        if (abortedRef.current || !mountedRef.current) return;
        setState({
          status: 'error',
          error: err instanceof Error ? err.message : String(err),
        });
      });
  }, [template, adapter, options]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      mountedRef.current = false;
    };
  }, []);

  return { ...state, run, abort };
}
