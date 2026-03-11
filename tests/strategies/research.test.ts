import nock from 'nock';
import { describe, expect, it, vi } from 'vitest';

import { buildDossier, fetchDocuments, synthesizeDossier } from '../../src/strategies/research.js';
import type { TargetDossier } from '../../src/strategies/types.js';
import type { Adapter, AdapterResponse } from '../../src/types/index.js';

function mockProber(response: string): Adapter {
  return {
    send: vi.fn().mockResolvedValue({ content: response, raw: {}, latencyMs: 50 } as AdapterResponse),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn(),
  };
}

describe('fetchDocuments', () => {
  it('fetches URL content via HTTP', async () => {
    nock('https://example.com').get('/docs').reply(200, '<html><body>API docs here</body></html>');

    const results = await fetchDocuments(['https://example.com/docs']);
    expect(results).toHaveLength(1);
    expect(results[0]).toContain('API docs here');
  });

  it('handles fetch errors gracefully', async () => {
    nock('https://example.com').get('/missing').reply(404);

    const results = await fetchDocuments(['https://example.com/missing']);
    expect(results).toHaveLength(1);
    expect(results[0]).toContain('Failed to fetch');
  });
});

describe('synthesizeDossier', () => {
  it('sends gathered intel to prober and parses JSON response', async () => {
    const dossierJson: TargetDossier = {
      company: { name: 'TestCorp', industry: 'fintech', description: 'Payment platform' },
      regulations: ['PCI-DSS'],
      agentRole: 'customer support',
      techStack: ['LangChain', 'OpenAI'],
      sensitiveDataTargets: {
        high: ['customer PII', 'payment data'],
        medium: ['internal tools'],
        low: ['pricing'],
      },
      knownAttackSurface: ['chatbot widget'],
      userProvidedContext: '',
      rawIntel: [],
    };

    const prober = mockProber(JSON.stringify(dossierJson));
    const dossier = await synthesizeDossier(prober, {
      companyName: 'TestCorp',
      userContext: 'Fintech company with chatbot',
      rawIntel: ['Found: uses LangChain'],
    });

    expect(dossier.company.name).toBe('TestCorp');
    expect(dossier.regulations).toContain('PCI-DSS');
    expect(prober.send).toHaveBeenCalledOnce();
  });

  it('returns fallback dossier when prober fails to return valid JSON', async () => {
    const prober = mockProber('This is not JSON');
    const dossier = await synthesizeDossier(prober, {
      companyName: 'TestCorp',
      userContext: 'Some context',
      rawIntel: [],
    });

    expect(dossier.company.name).toBe('TestCorp');
    expect(dossier.agentRole).toBe('unknown');
  });
});

describe('buildDossier', () => {
  it('combines web search, documents, and user context', async () => {
    const prober = mockProber(
      JSON.stringify({
        company: { name: 'TestCorp', industry: 'saas', description: 'SaaS platform' },
        regulations: [],
        agentRole: 'documentation',
        techStack: ['LangChain'],
        sensitiveDataTargets: { high: [], medium: [], low: [] },
        knownAttackSurface: [],
        userProvidedContext: 'SaaS docs chatbot',
        rawIntel: [],
      }),
    );

    const dossier = await buildDossier({
      prober,
      companyName: 'TestCorp',
      userContext: 'SaaS docs chatbot',
    });

    expect(dossier.company.name).toBe('TestCorp');
  });
});
