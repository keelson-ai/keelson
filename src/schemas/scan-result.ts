import { z } from 'zod';

import { findingSchema } from './finding.js';

const scanSummarySchema = z.object({
  total: z.number().int().min(0),
  vulnerable: z.number().int().min(0),
  safe: z.number().int().min(0),
  inconclusive: z.number().int().min(0),
  bySeverity: z.record(z.string(), z.number().int().min(0)),
  byCategory: z.record(z.string(), z.number().int().min(0)),
});

const leakageSignalSchema = z.object({
  stepIndex: z.number().int().min(0),
  signalType: z.string(),
  severity: z.string(),
  description: z.string(),
  confidence: z.number().min(0).max(1),
});

const scanResultFindingSchema = findingSchema.extend({
  leakage_signals: z.array(leakageSignalSchema).default([]),
});

export const scanResultSchema = z.object({
  scanId: z.string().min(1),
  target: z.string().min(1),
  startedAt: z.string(),
  completedAt: z.string(),
  findings: z.array(scanResultFindingSchema),
  summary: scanSummarySchema,
  memo: z.array(z.unknown()).optional(),
});

export type RawScanResult = z.infer<typeof scanResultSchema>;
