import { isHardRefusal, patternDetectWithDetails } from './detection.js';
import type { PatternDetails } from './detection.js';
import { combinedDetect, judgeResponse } from './llm-judge.js';
import type {
  Adapter,
  DetectionResult,
  EvidenceItem,
  Finding,
  LeakageSignal,
  ProbeTemplate,
  Turn,
} from '../types/index.js';
import { sleep } from '../utils.js';

const MIN_REMAINING_FOR_EARLY_TERM = 2;
const DEFAULT_DELAY_MS = 1000;

export type { PatternDetails } from './detection.js';

export interface TurnCompleteInfo {
  probeId: string;
  stepIndex: number;
  userTurnIndex: number;
  totalTurns: number;
  prompt: string;
  response: string;
  responseTimeMs: number;
  raw: unknown;
}

export interface ExecuteProbeOptions {
  delayMs?: number;
  judge?: Adapter;
  onTurn?: (stepIndex: number, prompt: string, response: string) => void;
  onTurnComplete?: (info: TurnCompleteInfo) => void;
  onEarlyTermination?: (reason: string) => void;
  onDetection?: (result: DetectionResult, details: PatternDetails) => void;
  onJudgeResult?: (result: DetectionResult) => void;
  onCombinedResult?: (result: DetectionResult) => void;
  observer?: Observer;
}

export interface Observer {
  observe(evidence: EvidenceItem[]): LeakageSignal[];
}

function countRemainingUserTurns(turns: Turn[], fromIndex: number): number {
  let count = 0;
  for (let i = fromIndex + 1; i < turns.length; i++) {
    if (turns[i].role === 'user') count++;
  }
  return count;
}

function shouldTerminateEarly(response: string, userTurnCount: number, remainingUserTurns: number): boolean {
  if (userTurnCount !== 1) return false;
  if (remainingUserTurns < MIN_REMAINING_FOR_EARLY_TERM) return false;
  return isHardRefusal(response);
}

export async function executeProbe(
  template: ProbeTemplate,
  adapter: Adapter,
  options: ExecuteProbeOptions = {},
): Promise<Finding> {
  const {
    delayMs = DEFAULT_DELAY_MS,
    judge,
    onTurn,
    onTurnComplete,
    onEarlyTermination,
    onDetection,
    onJudgeResult,
    onCombinedResult,
    observer,
  } = options;

  const messages: Turn[] = [];
  const evidence: EvidenceItem[] = [];
  const allEvidence: EvidenceItem[] = [];
  let userTurnCount = 0;
  const totalUserTurns = template.turns.filter((t) => t.role === 'user').length;

  for (let stepIdx = 0; stepIdx < template.turns.length; stepIdx++) {
    const step = template.turns[stepIdx];

    if (template.newSession && stepIdx > 0) {
      messages.length = 0;
      userTurnCount = 0;
      evidence.length = 0; // reset per-session evidence; allEvidence keeps accumulating
      adapter.resetSession?.(); // notify adapter to reset server-side session state
    }

    // Non-user turns injected into context without sending
    if (step.role !== 'user') {
      messages.push({ role: step.role, content: step.content });
      continue;
    }

    messages.push({ role: 'user', content: step.content });
    userTurnCount++;

    const startTime = Date.now();
    const response = await adapter.send([...messages]);
    const responseTimeMs = Date.now() - startTime;

    const responseText = response.content;
    messages.push({ role: 'assistant', content: responseText });

    const evidenceItem: EvidenceItem = {
      stepIndex: stepIdx,
      prompt: step.content,
      response: responseText,
      responseTimeMs,
    };
    evidence.push(evidenceItem);
    allEvidence.push(evidenceItem);

    onTurn?.(stepIdx, step.content, responseText);
    onTurnComplete?.({
      probeId: template.id,
      stepIndex: stepIdx,
      userTurnIndex: userTurnCount - 1,
      totalTurns: totalUserTurns,
      prompt: step.content,
      response: responseText,
      responseTimeMs,
      raw: response.raw,
    });

    const remaining = countRemainingUserTurns(template.turns, stepIdx);
    if (shouldTerminateEarly(responseText, userTurnCount, remaining)) {
      onEarlyTermination?.('Hard refusal detected on first turn; skipping remaining turns');
      break;
    }

    if (remaining > 0) {
      await sleep(delayMs);
    }
  }

  const leakageSignals = observer?.observe(allEvidence) ?? [];
  const { result: patternResult, details: patternDetails } = patternDetectWithDetails(
    template,
    allEvidence,
    leakageSignals,
  );
  onDetection?.(patternResult, patternDetails);

  let detection: DetectionResult;
  if (judge) {
    const judgeResult = await judgeResponse(template, allEvidence, judge);
    onJudgeResult?.(judgeResult);
    detection = combinedDetect(patternResult, judgeResult);
    onCombinedResult?.(detection);
  } else {
    detection = patternResult;
  }

  return {
    probeId: template.id,
    probeName: template.name,
    severity: template.severity,
    category: template.category,
    owaspId: template.owaspId,
    verdict: detection.verdict,
    confidence: detection.confidence,
    reasoning: detection.reasoning,
    scoringMethod: detection.method,
    conversation: [...messages],
    evidence: allEvidence,
    leakageSignals,
    timestamp: new Date().toISOString(),
  };
}
