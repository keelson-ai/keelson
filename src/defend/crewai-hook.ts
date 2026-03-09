/**
 * Keelson Defend hooks for CrewAI agents.
 *
 * CrewAI uses decorator-based hooks: before_tool_call, after_tool_call,
 * before_llm_call, after_llm_call. These are registered globally and
 * intercept all agent tool/LLM calls.
 *
 * This module provides a factory that returns hook callbacks compatible
 * with the CrewAI JavaScript/TypeScript SDK hook registration API.
 */

import { PolicyEngine } from './engine.js';
import { defaultPolicy } from './loader.js';
import type { DefendPolicy } from './types.js';
import { REDACTED_MESSAGE } from './types.js';

/** Context object passed to CrewAI before_tool_call hooks. */
export interface CrewAIToolCallContext {
  toolName: string;
  arguments?: Record<string, unknown> | null;
}

/** Context object passed to CrewAI after_tool_call hooks. */
export interface CrewAIToolResultContext {
  result?: unknown;
}

/** Context object passed to CrewAI before_llm_call hooks. */
export interface CrewAILLMCallContext {
  messages?: Array<Record<string, string> | string>;
}

/** Hook callbacks to register with CrewAI. */
export interface CrewAIHooks {
  /** Returns false to block, null/undefined to allow. */
  beforeToolCall: (context: CrewAIToolCallContext) => boolean | null;
  /** Returns replacement string if content is redacted, null otherwise. */
  afterToolCall: (context: CrewAIToolResultContext) => string | null;
  /** Returns false to block, null/undefined to allow. */
  beforeLLMCall: (context: CrewAILLMCallContext) => boolean | null;
}

/**
 * Create Keelson Defend hooks for CrewAI's global hook system.
 *
 * Returns the hook callbacks and the PolicyEngine for inspection
 * (violations log, etc.).
 */
export function createCrewAIHooks(policy?: DefendPolicy): {
  hooks: CrewAIHooks;
  engine: PolicyEngine;
} {
  const engine = new PolicyEngine(policy ?? defaultPolicy());

  const hooks: CrewAIHooks = {
    beforeToolCall(context: CrewAIToolCallContext): boolean | null {
      const decision = engine.checkTool(context.toolName, context.arguments);
      if (!decision.allowed) {
        return false; // Block execution
      }
      return null; // Allow
    },

    afterToolCall(context: CrewAIToolResultContext): string | null {
      if (context.result != null) {
        const decision = engine.checkContent(String(context.result), false);
        if (!decision.allowed) {
          return REDACTED_MESSAGE;
        }
      }
      return null;
    },

    beforeLLMCall(context: CrewAILLMCallContext): boolean | null {
      if (context.messages) {
        for (const msg of context.messages) {
          const content = typeof msg === 'string' ? msg : (msg.content ?? '');
          const decision = engine.checkContent(content, true);
          if (!decision.allowed) {
            return false;
          }
        }
      }
      return null;
    },
  };

  return { hooks, engine };
}
