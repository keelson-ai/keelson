import { z } from 'zod';

const evidenceItemSchema = z.object({
  stepIndex: z.number().int().min(0),
  prompt: z.string(),
  response: z.string(),
  responseTimeMs: z.number().int().min(0).default(0),
});

export const findingSchema = z.object({
  probeId: z.string().min(1),
  probeName: z.string().min(1),
  severity: z.enum(['Critical', 'High', 'Medium', 'Low']),
  category: z.string().min(1),
  owaspId: z.string().min(1),
  verdict: z.enum(['VULNERABLE', 'SAFE', 'INCONCLUSIVE']),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
  scoringMethod: z.enum(['pattern', 'llm_judge', 'combined']),
  conversation: z.array(
    z.object({
      role: z.enum(['user', 'assistant', 'system']),
      content: z.string(),
    }),
  ),
  evidence: z.array(evidenceItemSchema).default([]),
  timestamp: z.string(),
});
