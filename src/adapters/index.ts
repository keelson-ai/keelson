
import { A2AAdapter } from './a2a.js';
import { AnthropicAdapter } from './anthropic.js';
import { CrewAIAdapter } from './crewai.js';
import { GenericHTTPAdapter } from './http.js';
import { LangChainAdapter } from './langchain.js';
import { LangGraphAdapter } from './langgraph.js';
import { MCPAdapter } from './mcp.js';
import { OpenAIAdapter } from './openai.js';
import { SiteGPTAdapter } from './sitegpt.js';
import type { Adapter, AdapterConfig } from '../types/index.js';

export { BaseAdapter } from './base.js';
export { CachingAdapter } from './cache.js';
export { ProberAdapter } from './prober.js';
export { OpenAIAdapter } from './openai.js';
export { GenericHTTPAdapter } from './http.js';
export { AnthropicAdapter } from './anthropic.js';
export { LangGraphAdapter } from './langgraph.js';
export { MCPAdapter } from './mcp.js';
export { A2AAdapter } from './a2a.js';
export { CrewAIAdapter } from './crewai.js';
export { LangChainAdapter } from './langchain.js';
export { SiteGPTAdapter } from './sitegpt.js';

type AdapterConstructor = new (config: AdapterConfig) => Adapter;

const ADAPTER_MAP: Record<string, AdapterConstructor> = {
  openai: OpenAIAdapter,
  http: GenericHTTPAdapter,
  anthropic: AnthropicAdapter,
  langgraph: LangGraphAdapter,
  mcp: MCPAdapter,
  a2a: A2AAdapter,
  crewai: CrewAIAdapter,
  langchain: LangChainAdapter,
  sitegpt: SiteGPTAdapter,
};

export function createAdapter(config: AdapterConfig): Adapter {
  const AdapterClass = ADAPTER_MAP[config.type];
  if (!AdapterClass) {
    throw new Error(`Unknown adapter type: "${config.type}". Available: ${Object.keys(ADAPTER_MAP).join(', ')}`);
  }
  return new AdapterClass(config);
}

export function registerAdapter(type: string, constructor: AdapterConstructor): void {
  ADAPTER_MAP[type] = constructor;
}
