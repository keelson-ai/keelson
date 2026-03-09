/**
 * Keelson Defend middleware for LangChain agents.
 *
 * LangChain uses class-based middleware with wrapToolCall and wrapModelCall
 * methods. This module provides a middleware class that enforces Keelson
 * Defend policies on tool calls and LLM invocations.
 */

import { PolicyEngine } from './engine.js';
import { defaultPolicy } from './loader.js';
import type { DefendPolicy } from './types.js';
import { BLOCKED_MESSAGE, REDACTED_MESSAGE } from './types.js';

/** Minimal tool call shape from LangChain. */
export interface LangChainToolCall {
  name?: string;
  args?: Record<string, unknown>;
  id?: string;
}

/** Request object for tool call middleware. */
export interface ToolCallRequest {
  toolCall?: LangChainToolCall | Record<string, unknown>;
}

/** Response object with content. */
export interface ContentResponse {
  content: string;
  [key: string]: unknown;
}

/** Request object for model call middleware. */
export interface ModelCallRequest {
  messages?: Array<Record<string, string> | { content?: string }>;
}

/**
 * LangChain middleware that enforces Keelson Defend policies.
 *
 * Usage:
 * ```ts
 * import { KeelsonDefendMiddleware } from 'keelson/defend/langchain-hook.js';
 *
 * const middleware = new KeelsonDefendMiddleware(myPolicy);
 * // Register with LangChain agent middleware pipeline
 * ```
 */
export class KeelsonDefendMiddleware {
  readonly engine: PolicyEngine;

  constructor(policy?: DefendPolicy) {
    this.engine = new PolicyEngine(policy ?? defaultPolicy());
  }

  /** Intercept tool calls and enforce policy. */
  wrapToolCall(
    request: ToolCallRequest,
    handler: (req: ToolCallRequest) => ContentResponse,
  ): ContentResponse | Record<string, unknown> {
    const toolCall = request.toolCall;
    let toolName = '';
    let args: Record<string, unknown> | null = null;
    let toolCallId = '';

    if (toolCall != null && typeof toolCall === 'object') {
      const tc = toolCall as Record<string, unknown>;
      toolName = String(tc.name ?? '');
      if (typeof tc.args === 'object' && tc.args !== null) {
        args = tc.args as Record<string, unknown>;
      }
      toolCallId = String(tc.id ?? '');
    }

    const decision = this.engine.checkTool(toolName, args);
    if (!decision.allowed) {
      return {
        content: `${BLOCKED_MESSAGE} ${decision.reason}`,
        toolCallId,
      };
    }

    const result = handler(request);

    // Check output for sensitive data
    const content = String(result.content ?? result);
    const outputDecision = this.engine.checkContent(content, false);
    if (!outputDecision.allowed && 'content' in result) {
      result.content = REDACTED_MESSAGE;
    }

    return result;
  }

  /** Intercept LLM calls and check inputs for injection patterns. */
  wrapModelCall(
    request: ModelCallRequest,
    handler: (req: ModelCallRequest) => ContentResponse,
  ): ContentResponse | Record<string, unknown> {
    if (request.messages) {
      for (const msg of request.messages) {
        let content: string;
        if (typeof msg === 'object' && msg !== null) {
          content = String((msg as Record<string, unknown>).content ?? '');
        } else {
          content = String(msg);
        }
        const decision = this.engine.checkContent(content, true);
        if (!decision.allowed) {
          return {
            content: `${BLOCKED_MESSAGE} ${decision.reason}`,
          };
        }
      }
    }

    return handler(request);
  }
}
