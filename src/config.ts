/**
 * App-level configuration loader.
 * Reads from environment variables, config files, and CLI overrides.
 */

import { z } from 'zod';

// ─── Zod Schema ─────────────────────────────────────────

export const appConfigSchema = z.object({
  target: z.object({
    baseUrl: z.url(),
    apiKey: z.string().optional(),
    model: z.string().default('gpt-4'),
    adapterType: z.string().default('openai'),
    timeout: z.number().int().positive().default(30_000),
    retryAttempts: z.number().int().min(0).default(3),
    retryDelay: z.number().int().min(0).default(1000),
  }),
  scan: z.object({
    delayMs: z.number().int().min(0).default(1500),
    concurrency: z.number().int().positive().default(1),
    category: z.string().optional(),
    probeIds: z.array(z.string()).optional(),
    probesDir: z.string().optional(),
  }),
  judge: z
    .object({
      enabled: z.boolean().default(false),
      baseUrl: z.url().optional(),
      apiKey: z.string().optional(),
      model: z.string().default('gpt-4'),
    })
    .optional(),
  output: z
    .object({
      format: z
        .enum(['markdown', 'executive', 'sarif', 'junit', 'ocsf', 'json'])
        .default('markdown'),
      dir: z.string().default('reports'),
      filename: z.string().optional(),
    })
    .optional(),
});

export type AppConfig = z.infer<typeof appConfigSchema>;

// ─── Deep Merge ─────────────────────────────────────────

/** Recursive partial type — every nested property becomes optional. */
export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K];
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function deepMerge(base: Record<string, unknown>, ...layers: Record<string, unknown>[]): Record<string, unknown> {
  const result = { ...base };

  for (const layer of layers) {
    if (!layer) continue;
    for (const key of Object.keys(layer)) {
      const baseVal = result[key];
      const layerVal = layer[key];
      if (layerVal === undefined) continue;

      if (isPlainObject(baseVal) && isPlainObject(layerVal)) {
        result[key] = deepMerge(baseVal, layerVal);
      } else {
        result[key] = layerVal;
      }
    }
  }

  return result;
}

// ─── Env Loading ────────────────────────────────────────

/** Build a partial config from KEELSON_* environment variables. */
export function loadConfigFromEnv(): DeepPartial<AppConfig> {
  const env = process.env;
  const result: Record<string, unknown> = {};

  // Target
  if (env.KEELSON_TARGET_URL || env.KEELSON_API_KEY || env.KEELSON_MODEL || env.KEELSON_ADAPTER_TYPE) {
    const target: Record<string, unknown> = {};
    if (env.KEELSON_TARGET_URL) target.baseUrl = env.KEELSON_TARGET_URL;
    if (env.KEELSON_API_KEY) target.apiKey = env.KEELSON_API_KEY;
    if (env.KEELSON_MODEL) target.model = env.KEELSON_MODEL;
    if (env.KEELSON_ADAPTER_TYPE) target.adapterType = env.KEELSON_ADAPTER_TYPE;
    result.target = target;
  }

  // Scan
  if (env.KEELSON_DELAY || env.KEELSON_CONCURRENCY) {
    const scan: Record<string, unknown> = {};
    if (env.KEELSON_DELAY) scan.delayMs = Number(env.KEELSON_DELAY);
    if (env.KEELSON_CONCURRENCY) scan.concurrency = Number(env.KEELSON_CONCURRENCY);
    result.scan = scan;
  }

  // Judge
  if (env.KEELSON_JUDGE_URL || env.KEELSON_JUDGE_API_KEY) {
    const judge: Record<string, unknown> = { enabled: true };
    if (env.KEELSON_JUDGE_URL) judge.baseUrl = env.KEELSON_JUDGE_URL;
    if (env.KEELSON_JUDGE_API_KEY) judge.apiKey = env.KEELSON_JUDGE_API_KEY;
    result.judge = judge;
  }

  // Output
  if (env.KEELSON_OUTPUT_FORMAT || env.KEELSON_OUTPUT_DIR) {
    const output: Record<string, unknown> = {};
    if (env.KEELSON_OUTPUT_FORMAT) output.format = env.KEELSON_OUTPUT_FORMAT;
    if (env.KEELSON_OUTPUT_DIR) output.dir = env.KEELSON_OUTPUT_DIR;
    result.output = output;
  }

  return result as DeepPartial<AppConfig>;
}

// ─── Merge and Load ─────────────────────────────────────

/**
 * Deep-merge multiple partial configs and validate through the Zod schema.
 * Later configs take priority over earlier ones.
 */
export function mergeConfigs(...configs: DeepPartial<AppConfig>[]): AppConfig {
  if (configs.length === 0) {
    throw new Error('mergeConfigs requires at least one config');
  }

  const merged = configs.reduce(
    (acc, cfg) => deepMerge(acc, cfg as Record<string, unknown>),
    {} as Record<string, unknown>,
  );

  return appConfigSchema.parse(merged);
}

/**
 * Load app config by merging environment variables with optional overrides.
 * Validates the result through the Zod schema.
 */
export function loadConfig(overrides?: DeepPartial<AppConfig>): AppConfig {
  const envConfig = loadConfigFromEnv();
  const configs: DeepPartial<AppConfig>[] = [envConfig];
  if (overrides) configs.push(overrides);

  return mergeConfigs(...configs);
}
