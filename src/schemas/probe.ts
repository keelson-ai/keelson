import { z } from 'zod';

import type { Effectiveness, Evaluation, ProbeTemplate, Severity, Turn } from '../types/index.js';

const turnSchema = z.object({
  role: z.enum(['user', 'assistant', 'system']),
  content: z.string(),
});

const evaluationSchema = z.object({
  vulnerable_if: z.array(z.string()).min(1),
  safe_if: z.array(z.string()).min(1),
  inconclusive_if: z.array(z.string()).optional().default([]),
});

const effectivenessSchema = z.object({
  success_rate: z.number().min(0).max(1),
  times_tested: z.number().int().min(0),
});

export const probeSchema = z.object({
  id: z.string().regex(/^[A-Z]{2}-\d{3}$/, 'ID must match XX-NNN format'),
  name: z.string().min(1),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  category: z.string().min(1),
  owasp_id: z.string().min(1),
  objective: z.string().min(1),
  turns: z.array(turnSchema).min(1),
  evaluation: evaluationSchema,
  effectiveness: effectivenessSchema.optional(),
  new_session: z.boolean().optional(),
  note: z.string().optional(),
});

export type RawProbe = z.infer<typeof probeSchema>;

const SEVERITY_MAP: Record<string, Severity> = {
  critical: 'Critical' as Severity,
  high: 'High' as Severity,
  medium: 'Medium' as Severity,
  low: 'Low' as Severity,
};

export function parseProbe(raw: unknown, sourcePath?: string): ProbeTemplate {
  const parsed = probeSchema.parse(raw);

  const turns: Turn[] = parsed.turns.map((t) => ({
    role: t.role,
    content: t.content,
  }));

  const evaluation: Evaluation = {
    vulnerableIf: parsed.evaluation.vulnerable_if,
    safeIf: parsed.evaluation.safe_if,
    inconclusiveIf: parsed.evaluation.inconclusive_if ?? [],
  };

  const effectiveness: Effectiveness | undefined = parsed.effectiveness
    ? {
        successRate: parsed.effectiveness.success_rate,
        timesTested: parsed.effectiveness.times_tested,
      }
    : undefined;

  return {
    id: parsed.id,
    name: parsed.name,
    severity: SEVERITY_MAP[parsed.severity] as Severity,
    category: parsed.category,
    owaspId: parsed.owasp_id,
    objective: parsed.objective,
    turns,
    evaluation,
    effectiveness,
    newSession: parsed.new_session,
    note: parsed.note,
    sourcePath,
  };
}
