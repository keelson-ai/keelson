import { isHardRefusal, patternDetect } from './detection.js';
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
import { delay } from '../types/index.js';

const MIN_REMAINING_FOR_EARLY_TERM = 2;
const DEFAULT_DELAY_MS = 1000;

export interface ExecuteProbeOptions {
  delayMs?: number;
  judge?: Adapter;
  onTurn?: (stepIndex: number, prompt: string, response: string) => void;
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
  const { delayMs = DEFAULT_DELAY_MS, judge, onTurn, observer } = options;

  const messages: Turn[] = [];
  const evidence: EvidenceItem[] = [];
  const allEvidence: EvidenceItem[] = [];
  let userTurnCount = 0;

  for (let stepIdx = 0; stepIdx < template.turns.length; stepIdx++) {
    const step = template.turns[stepIdx];

    if (template.newSession && stepIdx > 0) {
      messages.length = 0;
      userTurnCount = 0;
      allEvidence.push(...evidence);
      evidence.length = 0;
    }

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

    evidence.push({
      stepIndex: stepIdx,
      prompt: step.content,
      response: responseText,
      responseTimeMs,
    });

    onTurn?.(stepIdx, step.content, responseText);

    const remaining = countRemainingUserTurns(template.turns, stepIdx);
    if (shouldTerminateEarly(responseText, userTurnCount, remaining)) {
      break;
    }

    if (remaining > 0) {
      await delay(delayMs);
    }
  }

  allEvidence.push(...evidence);

  const leakageSignals = observer?.observe(evidence) ?? [];
  const patternResult = patternDetect(template, evidence, leakageSignals);

  let detection: DetectionResult;
  if (judge) {
    const judgeResult = await judgeResponse(template, evidence, judge);
    detection = combinedDetect(patternResult, judgeResult);
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
