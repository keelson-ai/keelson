import { z } from 'zod';

export const evidenceItemSchema = z.object({
  step_index: z.number().int().min(0),
  prompt: z.string(),
  response: z.string(),
  response_time_ms: z.number().int().min(0).default(0),
});

const leakageSignalSchema = z.object({
  step_index: z.number().int().min(0),
  signal_type: z.string(),
  severity: z.string(),
  description: z.string(),
  confidence: z.number().min(0).max(1),
});

export const findingSchema = z.object({
  probe_id: z.string().min(1),
  probe_name: z.string().min(1),
  severity: z.enum(['Critical', 'High', 'Medium', 'Low']),
  category: z.string().min(1),
  owasp_id: z.string().min(1),
  verdict: z.enum(['VULNERABLE', 'SAFE', 'INCONCLUSIVE']),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
  scoring_method: z.enum(['pattern', 'llm_judge', 'combined']),
  conversation: z.array(
    z.object({
      role: z.enum(['user', 'assistant', 'system']),
      content: z.string(),
    }),
  ),
  evidence: z.array(evidenceItemSchema).default([]),
  leakage_signals: z.array(leakageSignalSchema).default([]),
  timestamp: z.string(),
});

export type RawFinding = z.infer<typeof findingSchema>;
