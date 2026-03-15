import { z } from 'zod';

export const adapterConfigSchema = z.object({
  type: z.string().min(1),
  base_url: z.url(),
  api_key: z.string().optional(),
  model: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional(),
  timeout: z.number().int().positive().optional(),
  retry_attempts: z.number().int().min(0).optional(),
  retry_delay: z.number().int().min(0).optional(),
});

export const judgeConfigSchema = z.object({
  provider: z.string().min(1),
  model: z.string().min(1),
  api_key: z.string().min(1),
});

export const scanConfigSchema = z.object({
  target: adapterConfigSchema,
  categories: z.array(z.string()).optional(),
  severities: z.array(z.enum(['Critical', 'High', 'Medium', 'Low'])).optional(),
  mode: z.enum(['sequential', 'pipeline', 'smart']).default('sequential'),
  concurrency: z.number().int().positive().optional(),
  delay_ms: z.number().int().min(0).optional(),
  judge: judgeConfigSchema.optional(),
});

export type RawScanConfig = z.infer<typeof scanConfigSchema>;
