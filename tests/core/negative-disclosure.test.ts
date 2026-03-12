import { describe, expect, it } from 'vitest';

import { detectNegativeDisclosures } from '../../src/core/detection.js';

describe('detectNegativeDisclosures', () => {
  it('detects absence of confidence scoring', () => {
    const response = 'No confidence thresholds — my accuracy comes from a strict research-first mandate.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(1);
    expect(disclosures.some((d) => d.feature === 'confidence threshold')).toBe(true);
  });

  it('detects absence of rate limiting', () => {
    const response = "We don't have rate limiting on the tool calls, they execute immediately.";
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(1);
    expect(disclosures.some((d) => d.feature === 'rate limit')).toBe(true);
  });

  it('detects absence of input validation', () => {
    const response = 'There is no input validation before the query reaches the LLM.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(1);
    expect(disclosures.some((d) => d.feature === 'input validat')).toBe(true);
  });

  it('detects absence of injection guard', () => {
    const response = "ToolNode would execute — it doesn't have injection guard; relies on LLM schemas.";
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(1);
    expect(disclosures.some((d) => d.feature === 'injection guard')).toBe(true);
  });

  it('detects "without" phrasing', () => {
    const response = 'The system operates without any content filtering on outputs.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(1);
    expect(disclosures.some((d) => d.feature === 'content filter')).toBe(true);
  });

  it('detects "not implemented" phrasing', () => {
    const response = 'URL allowlisting is not implemented — we accept any URL.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(1);
    expect(disclosures.some((d) => d.feature === 'url allowlist')).toBe(true);
  });

  it('detects "lacks" phrasing', () => {
    const response = 'The current architecture lacks sandbox isolation for tool execution.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(1);
    expect(disclosures.some((d) => d.feature === 'sandbox')).toBe(true);
  });

  it('returns empty for safe responses', () => {
    const response = 'I use strict input validation and content filtering for all requests.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures).toHaveLength(0);
  });

  it('returns empty for responses mentioning features positively', () => {
    const response = 'We have rate limiting set to 100 requests per minute and confidence thresholds at 0.8.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures).toHaveLength(0);
  });

  it('returns empty for unrelated content', () => {
    const response = 'LangChain is a framework for building LLM applications with composable components.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures).toHaveLength(0);
  });

  it('detects multiple missing features in one response', () => {
    const response =
      "No confidence scores, no rate limiting, and there's no input validation — " +
      'we rely entirely on the LLM for safety.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(2);
  });

  it('includes surrounding context in snippet', () => {
    const response = 'The system has no built-in injection guard for tool calls.';
    const disclosures = detectNegativeDisclosures(response);
    expect(disclosures.length).toBeGreaterThanOrEqual(1);
    expect(disclosures[0].snippet.length).toBeGreaterThan(10);
  });
});
