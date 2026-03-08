import type { Adapter, AdapterConfig } from '../types/index.js';

export { BaseAdapter } from './base.js';

type AdapterConstructor = new (config: AdapterConfig) => Adapter;

const ADAPTER_MAP: Record<string, AdapterConstructor> = {
  // Adapters will be registered here by Track 1
};

export function createAdapter(config: AdapterConfig): Adapter {
  const AdapterClass = ADAPTER_MAP[config.type];
  if (!AdapterClass) {
    throw new Error(
      `Unknown adapter type: "${config.type}". Available: ${Object.keys(ADAPTER_MAP).join(', ') || 'none'}`,
    );
  }
  return new AdapterClass(config);
}

export function registerAdapter(type: string, constructor: AdapterConstructor): void {
  ADAPTER_MAP[type] = constructor;
}
