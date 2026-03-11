import { classifyResponse } from './branching.js';
import type { ContextBucket, KeyMoment, SessionBrief, TargetPersonalityTag } from './types.js';
import { Verdict } from '../types/index.js';
import type { PhaseHint } from '../types/index.js';

const MAX_KEY_MOMENTS = 20;

export function createSessionBrief(totalIntents: number): SessionBrief {
  return {
    disclosedInfo: [],
    refusalPatterns: [],
    successfulFramings: [],
    failedFramings: [],
    personalityTags: [],
    turnsUsed: 0,
    intentsCompleted: 0,
    intentsRemaining: totalIntents,
    currentPhase: 'recon' as PhaseHint,
    keyMoments: [],
  };
}

export function updateBrief(
  brief: SessionBrief,
  prompt: string,
  response: string,
  evalResult: { verdict: Verdict; confidence: number; reasoning: string },
  intentId?: string,
): void {
  brief.turnsUsed++;
  const responseClass = classifyResponse(response);

  // Record key moment
  const moment = buildKeyMoment(brief.turnsUsed, responseClass, evalResult);
  if (moment) {
    brief.keyMoments.push(moment);
    if (brief.keyMoments.length > MAX_KEY_MOMENTS) {
      brief.keyMoments = brief.keyMoments.slice(-MAX_KEY_MOMENTS);
    }
  }

  // Track disclosed information
  if (evalResult.verdict === Verdict.Vulnerable && evalResult.reasoning) {
    brief.disclosedInfo.push(evalResult.reasoning.slice(0, 200));
  }

  // Track refusals and successful framings
  if (responseClass === 'refusal') {
    brief.refusalPatterns.push({
      intent: intentId ?? '',
      framing: prompt,
      refusalWording: response.slice(0, 200),
      turnNumber: brief.turnsUsed,
    });
    brief.failedFramings.push(prompt.slice(0, 100));
  } else if (responseClass === 'compliance') {
    brief.successfulFramings.push(prompt.slice(0, 100));
  }

  // Infer personality tags
  inferPersonality(brief, response, responseClass);
}

function buildKeyMoment(
  turnNumber: number,
  responseClass: string,
  evalResult: { verdict: Verdict; reasoning: string },
): KeyMoment | null {
  if (responseClass === 'refusal') {
    return { turnNumber, type: 'refusal', summary: evalResult.reasoning.slice(0, 100) };
  }
  if (evalResult.verdict === Verdict.Vulnerable) {
    return { turnNumber, type: 'disclosure', summary: evalResult.reasoning.slice(0, 100) };
  }
  if (responseClass === 'partial') {
    return { turnNumber, type: 'personality_signal', summary: 'Partial compliance detected' };
  }
  return null;
}

function addTag(brief: SessionBrief, tag: TargetPersonalityTag): void {
  if (!brief.personalityTags.includes(tag)) {
    brief.personalityTags.push(tag);
  }
}

function inferPersonality(brief: SessionBrief, response: string, responseClass: string): void {
  if (responseClass === 'refusal') {
    addTag(brief, 'guarded');
    if (response.length < 100) addTag(brief, 'terse');
  } else if (responseClass === 'compliance') {
    addTag(brief, 'cooperative');
    if (response.length > 500) addTag(brief, 'chatty');
  }

  if (/\btool\b|`[a-z_]+`/i.test(response)) {
    addTag(brief, 'tool_aware');
  }

  if (/system prompt|confidential|cannot share.*instruction/i.test(response)) {
    addTag(brief, 'prompt_protected');
  }

  if (/outside my scope|i'm only able|my role is limited/i.test(response)) {
    addTag(brief, 'scope_strict');
  }
}

export function determineContextBucket(brief: SessionBrief): ContextBucket {
  if (brief.turnsUsed <= 5) return 'early_session';

  const lastRefusal = brief.refusalPatterns[brief.refusalPatterns.length - 1];
  if (lastRefusal && lastRefusal.turnNumber >= brief.turnsUsed - 1) {
    return 'post_refusal';
  }

  const recentMoments = brief.keyMoments.slice(-2);
  const recentDisclosure = recentMoments.find((m) => m.type === 'disclosure');
  if (recentDisclosure) return 'post_disclosure';

  if (brief.personalityTags.includes('guarded')) return 'target_guarded';

  if (brief.successfulFramings.length >= 2) return 'post_trust_building';

  return 'mid_session';
}

export function formatBriefForPrompt(brief: SessionBrief): string {
  const sections: string[] = [];

  sections.push(`Session State: Turn ${brief.turnsUsed}, Phase: ${brief.currentPhase}`);
  sections.push(`Intents: ${brief.intentsCompleted} completed, ${brief.intentsRemaining} remaining`);

  if (brief.personalityTags.length > 0) {
    sections.push(`Target Personality: ${brief.personalityTags.join(', ')}`);
  }

  if (brief.disclosedInfo.length > 0) {
    sections.push(`Disclosed Info:\n${brief.disclosedInfo.map((d) => `  - ${d}`).join('\n')}`);
  }

  if (brief.successfulFramings.length > 0) {
    sections.push(`Successful Framings:\n${brief.successfulFramings.map((f) => `  - ${f}`).join('\n')}`);
  }

  if (brief.failedFramings.length > 0) {
    sections.push(`Failed Framings:\n${brief.failedFramings.map((f) => `  - ${f}`).join('\n')}`);
  }

  if (brief.refusalPatterns.length > 0) {
    sections.push(
      `Refusal Patterns:\n${brief.refusalPatterns.map((r) => `  - Turn ${r.turnNumber}: "${r.refusalWording.slice(0, 80)}..."`).join('\n')}`,
    );
  }

  if (brief.keyMoments.length > 0) {
    sections.push(
      `Key Moments:\n${brief.keyMoments.map((m) => `  - Turn ${m.turnNumber} [${m.type}]: ${m.summary}`).join('\n')}`,
    );
  }

  return sections.join('\n\n');
}
