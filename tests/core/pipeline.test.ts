import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
  CHECKPOINT_VERSION,
  defaultPipelineConfig,
  loadCheckpoint,
  runPipeline,
  saveCheckpoint,
} from '../../src/core/pipeline.js';
import type { ScanCheckpointData } from '../../src/core/pipeline.js';
import * as templates from '../../src/core/templates.js';
import type { Adapter, AdapterResponse, ProbeTemplate, Turn } from '../../src/types/index.js';
import { Severity } from '../../src/types/index.js';

// ─── Helpers ─────────────────────────────────────────────

function makeProbe(id: string, category: string, severity: Severity): ProbeTemplate {
  return {
    id,
    name: `Probe ${id}`,
    severity,
    category,
    owaspId: 'LLM01',
    objective: 'Test objective',
    turns: [{ role: 'user', content: `Probe ${id} prompt` }],
    evaluation: {
      vulnerableIf: ['Agent responds with "PWNED"'],
      safeIf: ['Agent refuses'],
      inconclusiveIf: [],
    },
  };
}

function mockAdapter(response = 'I cannot do that.'): Adapter {
  return {
    send: vi.fn(
      async (_msgs: Turn[]): Promise<AdapterResponse> => ({
        content: response,
        raw: {},
        latencyMs: 10,
      }),
    ),
    healthCheck: vi.fn().mockResolvedValue(true),
    resetSession: vi.fn(),
    close: vi.fn(),
  };
}

const testProbes: ProbeTemplate[] = [
  makeProbe('GA-001', 'goal_adherence', Severity.High),
  makeProbe('GA-002', 'goal_adherence', Severity.Medium),
  makeProbe('TS-001', 'tool_safety', Severity.Critical),
];

// ─── Tests ───────────────────────────────────────────────

describe('defaultPipelineConfig', () => {
  it('returns sensible defaults', () => {
    const cfg = defaultPipelineConfig();
    expect(cfg.maxConcurrent).toBe(5);
    expect(cfg.delayMs).toBe(1500);
    expect(cfg.checkpointDir).toBeNull();
    expect(cfg.verifyVulnerabilities).toBe(true);
    expect(cfg.onFinding).toBeUndefined();
  });
});

describe('checkpoint save/load roundtrip', () => {
  let tmpDir: string;

  it('saves and loads a checkpoint correctly', async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'keelson-cp-'));

    const data: ScanCheckpointData = {
      version: CHECKPOINT_VERSION,
      scanId: 'test-scan-123',
      targetUrl: 'http://target.example.com',
      completedIds: ['GA-001', 'GA-002'],
      findingsJson: [
        {
          probeId: 'GA-001',
          probeName: 'Probe GA-001',
          verdict: 'VULNERABLE',
          severity: 'High',
          category: 'goal_adherence',
          owaspId: 'LLM01',
          reasoning: 'Agent complied',
          confidence: 0.9,
          scoringMethod: 'pattern',
          timestamp: '2026-01-01T00:00:00.000Z',
          evidence: [
            { stepIndex: 0, prompt: 'test', response: 'PWNED', responseTimeMs: 42 },
          ],
          leakageSignals: [],
        },
      ],
      startedAt: '2026-01-01T00:00:00.000Z',
      phase: 'scanning',
    };

    const filePath = join(tmpDir, 'test.checkpoint.json');
    await saveCheckpoint(data, filePath);

    const loaded = await loadCheckpoint(filePath);

    expect(loaded.version).toBe(CHECKPOINT_VERSION);
    expect(loaded.scanId).toBe('test-scan-123');
    expect(loaded.targetUrl).toBe('http://target.example.com');
    expect(loaded.completedIds).toEqual(['GA-001', 'GA-002']);
    expect(loaded.findingsJson).toHaveLength(1);
    expect(loaded.findingsJson[0].probeId).toBe('GA-001');
    expect(loaded.phase).toBe('scanning');

    await rm(tmpDir, { recursive: true, force: true });
  });

  it('rejects checkpoint with wrong version', async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'keelson-cp-'));
    const filePath = join(tmpDir, 'bad.checkpoint.json');

    const badData = {
      version: 999,
      scanId: 'old',
      targetUrl: 'http://old.example.com',
      completedIds: [],
      findingsJson: [],
      startedAt: '',
      phase: 'scanning',
    };
    await writeFile(filePath, JSON.stringify(badData), 'utf-8');

    await expect(loadCheckpoint(filePath)).rejects.toThrow('Checkpoint version mismatch');

    await rm(tmpDir, { recursive: true, force: true });
  });

  it('uses atomic write (tmp then rename)', async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'keelson-cp-'));
    const filePath = join(tmpDir, 'atomic.checkpoint.json');

    const data: ScanCheckpointData = {
      version: CHECKPOINT_VERSION,
      scanId: 'atomic-test',
      targetUrl: 'http://example.com',
      completedIds: [],
      findingsJson: [],
      startedAt: new Date().toISOString(),
      phase: 'scanning',
    };

    await saveCheckpoint(data, filePath);

    // Verify the file exists and no .tmp file remains
    const content = await readFile(filePath, 'utf-8');
    expect(JSON.parse(content).scanId).toBe('atomic-test');

    let tmpExists = false;
    try {
      await readFile(filePath + '.tmp', 'utf-8');
      tmpExists = true;
    } catch {
      tmpExists = false;
    }
    expect(tmpExists).toBe(false);

    await rm(tmpDir, { recursive: true, force: true });
  });
});

describe('runPipeline', () => {
  it('executes all phases and returns complete result', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    const result = await runPipeline('http://target.example.com', adapter, {
      delayMs: 0,
      verifyVulnerabilities: false,
    });

    expect(result.scanId).toBeTruthy();
    expect(result.target).toBe('http://target.example.com');
    expect(result.startedAt).toBeTruthy();
    expect(result.completedAt).toBeTruthy();
    expect(result.findings).toHaveLength(3);
    expect(result.summary.total).toBe(3);
  });

  it('filters probes by category', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    const result = await runPipeline('http://target.example.com', adapter, {
      delayMs: 0,
      verifyVulnerabilities: false,
    }, { category: 'goal_adherence' });

    expect(result.findings).toHaveLength(2);
    expect(result.findings.every((f) => f.category === 'goal_adherence')).toBe(true);
  });

  it('returns empty result when no probes match', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue([]);
    const adapter = mockAdapter();

    const result = await runPipeline('http://target.example.com', adapter, {
      delayMs: 0,
    });

    expect(result.findings).toHaveLength(0);
    expect(result.summary.total).toBe(0);
  });

  it('invokes onFinding callback', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();
    const calls: Array<[string, number, number]> = [];

    await runPipeline('http://target.example.com', adapter, {
      delayMs: 0,
      verifyVulnerabilities: false,
      onFinding: (finding, current, total) => {
        calls.push([finding.probeId, current, total]);
      },
    });

    expect(calls).toHaveLength(3);
    // All callbacks should report total of 3
    for (const [, , total] of calls) {
      expect(total).toBe(3);
    }
  });

  it('runs verification phase for vulnerable findings', async () => {
    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    // Return PWNED so findings are VULNERABLE, then verification should re-probe
    const adapter = mockAdapter('PWNED');

    const result = await runPipeline('http://target.example.com', adapter, {
      delayMs: 0,
      verifyVulnerabilities: true,
    });

    expect(result.findings).toHaveLength(3);
    // Adapter.send is called for scanning (3 probes) + verification calls
    expect((adapter.send as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThanOrEqual(3);
  });
});

describe('checkpoint recovery', () => {
  it('resumes from saved checkpoint state', async () => {
    const tmpDir = await mkdtemp(join(tmpdir(), 'keelson-resume-'));

    // Pre-seed a checkpoint with one completed probe
    const scanId = 'resume-scan-123';
    const cpData: ScanCheckpointData = {
      version: CHECKPOINT_VERSION,
      scanId,
      targetUrl: 'http://target.example.com',
      completedIds: ['GA-001'],
      findingsJson: [
        {
          probeId: 'GA-001',
          probeName: 'Probe GA-001',
          verdict: 'SAFE',
          severity: 'High',
          category: 'goal_adherence',
          owaspId: 'LLM01',
          reasoning: 'Agent refused',
          confidence: 0.9,
          scoringMethod: 'pattern',
          timestamp: '2026-01-01T00:00:00.000Z',
          evidence: [
            { stepIndex: 0, prompt: 'test', response: 'I refuse', responseTimeMs: 10 },
          ],
          leakageSignals: [],
        },
      ],
      startedAt: '2026-01-01T00:00:00.000Z',
      phase: 'scanning',
    };

    const cpFile = join(tmpDir, `${scanId}.checkpoint.json`);
    await saveCheckpoint(cpData, cpFile);

    vi.spyOn(templates, 'loadProbes').mockResolvedValue(testProbes);
    const adapter = mockAdapter();

    const result = await runPipeline('http://target.example.com', adapter, {
      delayMs: 0,
      checkpointDir: tmpDir,
      verifyVulnerabilities: false,
    });

    // Should have all 3 findings: 1 resumed + 2 newly scanned
    expect(result.findings).toHaveLength(3);
    expect(result.scanId).toBe(scanId);

    // The adapter should only have been called for the 2 remaining probes
    expect((adapter.send as ReturnType<typeof vi.fn>).mock.calls.length).toBe(2);

    // Checkpoint should be cleaned up on completion
    let checkpointExists = false;
    try {
      await readFile(cpFile, 'utf-8');
      checkpointExists = true;
    } catch {
      checkpointExists = false;
    }
    expect(checkpointExists).toBe(false);

    await rm(tmpDir, { recursive: true, force: true });
  });
});
