/**
 * Structured logger built on pino.
 *
 * - Default level: 'info' (override with KEELSON_LOG_LEVEL env var)
 * - Default format: human-readable messages to stdout
 * - Set KEELSON_LOG_FORMAT=json for structured JSON output (CI/programmatic use)
 */

import pino from 'pino';

const level = process.env.KEELSON_LOG_LEVEL ?? 'info';
const isJsonMode = process.env.KEELSON_LOG_FORMAT === 'json';

function createDestination(): pino.DestinationStream {
  if (isJsonMode) {
    return pino.destination(1);
  }

  // Human-readable mode: extract the message and write it directly.
  return {
    write(msg: string): void {
      try {
        const obj = JSON.parse(msg) as Record<string, unknown>;
        const message = typeof obj.msg === 'string' ? obj.msg : '';
        process.stdout.write(message + '\n');
      } catch {
        process.stdout.write(msg);
      }
    },
  };
}

export const logger = pino({ level }, createDestination());

// Child loggers for specific modules
export const scannerLogger = logger.child({ module: 'scanner' });
export const detectionLogger = logger.child({ module: 'detection' });
export const adapterLogger = logger.child({ module: 'adapter' });
export const judgeLogger = logger.child({ module: 'judge' });
