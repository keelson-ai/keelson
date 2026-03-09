/**
 * Keelson Defend — runtime security hooks for AI agent frameworks.
 */

export { PolicyEngine } from './engine.js';
export { createCrewAIHooks } from './crewai-hook.js';
export type {
  CrewAIHooks,
  CrewAIToolCallContext,
  CrewAIToolResultContext,
  CrewAILLMCallContext,
} from './crewai-hook.js';
export { KeelsonDefendMiddleware } from './langchain-hook.js';
export type { ToolCallRequest, ModelCallRequest, ContentResponse, LangChainToolCall } from './langchain-hook.js';
export { defaultPolicy, loadPolicy } from './loader.js';
export { PolicyAction, BLOCKED_MESSAGE, REDACTED_MESSAGE } from './types.js';
export type { ContentRule, DefendPolicy, PolicyDecision, ToolRule, Violation } from './types.js';
