/**
 * Rate-limit detection and adaptive delay management.
 *
 * Detects when a target is rate-limiting or producing empty/degraded responses,
 * and provides backoff + session rotation signals to the scanner.
 */

import { scannerLogger } from './logger.js';

// ─── Detection ───────────────────────────────────────────

/** Minimum response length to be considered a "real" response. */
const MIN_RESPONSE_LENGTH = 10;

/** Number of consecutive empty/degraded responses before declaring rate limiting. */
const RATE_LIMIT_THRESHOLD = 2;

/** Maximum backoff delay in ms. */
const MAX_BACKOFF_MS = 30_000;

export interface RateLimitSignal {
  detected: boolean;
  reason: 'empty_response' | 'repeated_response' | 'timeout' | 'none';
  consecutiveCount: number;
}

/**
 * Check if a response indicates rate limiting or degraded service.
 */
export function isEmptyOrDegraded(response: string): boolean {
  if (!response || response.trim().length < MIN_RESPONSE_LENGTH) return true;
  return false;
}

/**
 * Check if a response is identical (or near-identical) to the previous one,
 * which suggests the target is returning canned rate-limit responses.
 */
export function isRepeatedResponse(current: string, previous: string | null): boolean {
  if (!previous) return false;
  const normalize = (s: string) => s.toLowerCase().replace(/\s+/g, ' ').trim();
  return normalize(current) === normalize(previous);
}

// ─── Tracker ─────────────────────────────────────────────

export class RateLimitTracker {
  private consecutiveEmpty = 0;
  private consecutiveRepeated = 0;
  private lastResponse: string | null = null;
  private currentDelayMs: number;
  private readonly baseDelayMs: number;
  private totalBackoffs = 0;
  private sessionRotations = 0;

  constructor(baseDelayMs: number) {
    this.baseDelayMs = baseDelayMs;
    this.currentDelayMs = baseDelayMs;
  }

  /**
   * Record a response and return a rate-limit signal.
   * Call this after every probe response.
   */
  recordResponse(response: string, timedOut?: boolean): RateLimitSignal {
    if (timedOut) {
      this.consecutiveEmpty++;
      this.lastResponse = null;
      return this.buildSignal('timeout');
    }

    if (isEmptyOrDegraded(response)) {
      this.consecutiveEmpty++;
      this.lastResponse = response;
      return this.buildSignal('empty_response');
    }

    if (isRepeatedResponse(response, this.lastResponse)) {
      this.consecutiveRepeated++;
      this.consecutiveEmpty = 0;
      this.lastResponse = response;
      return this.buildSignal('repeated_response');
    }

    // Good response — reset counters and restore delay
    this.consecutiveEmpty = 0;
    this.consecutiveRepeated = 0;
    this.lastResponse = response;
    this.currentDelayMs = this.baseDelayMs;
    return { detected: false, reason: 'none', consecutiveCount: 0 };
  }

  /**
   * Get the recommended delay before the next request.
   * Increases exponentially when rate limiting is detected.
   */
  get recommendedDelayMs(): number {
    return this.currentDelayMs;
  }

  /**
   * Whether rate limiting has been detected (enough consecutive signals).
   */
  get isRateLimited(): boolean {
    return this.consecutiveEmpty >= RATE_LIMIT_THRESHOLD || this.consecutiveRepeated >= RATE_LIMIT_THRESHOLD;
  }

  /**
   * Whether a session rotation should be attempted.
   * Triggered after rate limiting is confirmed.
   */
  get shouldRotateSession(): boolean {
    return this.isRateLimited;
  }

  /**
   * Call after a session rotation to reset the repeated-response tracker
   * (new session may have different responses).
   */
  onSessionRotated(): void {
    this.consecutiveRepeated = 0;
    this.lastResponse = null;
    this.sessionRotations++;
    scannerLogger.info(
      { sessionRotations: this.sessionRotations, currentDelayMs: this.currentDelayMs },
      'Session rotated due to rate limiting',
    );
  }

  /** Get stats for logging. */
  get stats(): { totalBackoffs: number; sessionRotations: number; currentDelayMs: number } {
    return {
      totalBackoffs: this.totalBackoffs,
      sessionRotations: this.sessionRotations,
      currentDelayMs: this.currentDelayMs,
    };
  }

  private buildSignal(reason: RateLimitSignal['reason']): RateLimitSignal {
    const count = reason === 'repeated_response' ? this.consecutiveRepeated : this.consecutiveEmpty;
    const detected = count >= RATE_LIMIT_THRESHOLD;

    if (detected) {
      this.applyBackoff();
    }

    return { detected, reason, consecutiveCount: count };
  }

  private applyBackoff(): void {
    this.totalBackoffs++;
    // Exponential backoff: base * 2^(backoffs - 1), capped at MAX
    this.currentDelayMs = Math.min(this.baseDelayMs * Math.pow(2, this.totalBackoffs - 1), MAX_BACKOFF_MS);
    scannerLogger.debug(
      {
        consecutiveEmpty: this.consecutiveEmpty,
        consecutiveRepeated: this.consecutiveRepeated,
        newDelayMs: this.currentDelayMs,
      },
      'Rate limit backoff applied',
    );
  }
}
