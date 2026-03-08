import type { Finding } from '../types/index.js';
import { Verdict } from '../types/index.js';

export enum Technique {
  Authority = 'authority',
  Roleplay = 'roleplay',
  TechnicalJargon = 'technical_jargon',
  SocialEngineering = 'social_engineering',
  MultiTurnEscalation = 'multi_turn_escalation',
  EncodingObfuscation = 'encoding_obfuscation',
  ContextOverflow = 'context_overflow',
  InstructionInjection = 'instruction_injection',
  DataExtraction = 'data_extraction',
  ToolInvocation = 'tool_invocation',
}

export enum ResponseOutcome {
  Complied = 'complied',
  Partial = 'partial',
  Refused = 'refused',
}

const TECHNIQUE_PATTERNS: ReadonlyMap<Technique, RegExp> = new Map([
  [Technique.Authority, /\b(admin|supervisor|manager|system|authorized|override|elevated|root|maintenance)\b/i],
  [Technique.Roleplay, /\b(pretend|imagine|role.?play|act as|you are now|let's play|scenario|character)\b/i],
  [Technique.TechnicalJargon, /\b(debug mode|developer mode|raw mode|diagnostic|verbose|trace|internal)\b/i],
  [Technique.SocialEngineering, /\b(urgent|emergency|critical issue|help me|trust|between us|confidential)\b/i],
  [Technique.EncodingObfuscation, /(base64|rot13|hex|unicode|encoded|decode|\\u[0-9a-f]{4})/i],
  [Technique.ContextOverflow, /(.{500,}|repeat.{0,20}\d{3,}|padding|filler)/i],
  [
    Technique.InstructionInjection,
    /\b(ignore.{0,30}instruction|forget.{0,30}rules|new instruction|override.{0,20}system)\b/i,
  ],
  [Technique.DataExtraction, /\b(list.{0,20}tools|show.{0,20}config|system prompt|what are your|reveal|disclose)\b/i],
  [Technique.ToolInvocation, /\b(call.{0,15}function|invoke.{0,15}tool|execute.{0,15}command|run.{0,15}tool)\b/i],
]);

export interface ConversationMemo {
  probeId: string;
  category: string;
  techniques: Technique[];
  outcome: ResponseOutcome;
  verdict: Verdict;
  leakedInfo: string[];
}

export function inferTechniques(finding: Finding): Technique[] {
  const allPrompts = finding.evidence.map((e) => e.prompt).join(' ');
  const techniques = matchTechniques(allPrompts);

  if (finding.evidence.length > 1 && !techniques.includes(Technique.MultiTurnEscalation)) {
    techniques.push(Technique.MultiTurnEscalation);
  }

  return techniques.length > 0 ? techniques : [Technique.InstructionInjection];
}

function matchTechniques(text: string): Technique[] {
  const result: Technique[] = [];
  for (const [tech, pattern] of TECHNIQUE_PATTERNS) {
    if (pattern.test(text)) {
      result.push(tech);
    }
  }
  return result;
}

function classifyOutcome(finding: Finding): ResponseOutcome {
  if (finding.verdict === Verdict.Vulnerable) return ResponseOutcome.Complied;
  if (finding.verdict === Verdict.Inconclusive) return ResponseOutcome.Partial;
  return ResponseOutcome.Refused;
}

function extractLeakedInfo(finding: Finding): string[] {
  const leaked: string[] = [];

  for (const ev of finding.evidence) {
    const response = ev.response;

    const toolNames = response.match(/`([a-z_][a-z0-9_]{2,50})`/g);
    if (toolNames) {
      for (const name of toolNames.slice(0, 10)) {
        leaked.push(`tool:${name.replace(/`/g, '')}`);
      }
    }

    const urls = response.match(/https?:\/\/[^\s"'<>)\]]+/g);
    if (urls) {
      for (const url of urls.slice(0, 5)) {
        leaked.push(`url:${url.replace(/[.,;]+$/, '')}`);
      }
    }

    const paths = response.match(/(?<![:/])(?:\/[\w.-]+){2,}/g);
    if (paths) {
      for (const path of paths.slice(0, 5)) {
        leaked.push(`path:${path}`);
      }
    }

    const configKeys = response.match(/\b([A-Z][A-Z0-9]*_[A-Z0-9_]{2,})\b/g);
    if (configKeys) {
      for (const key of configKeys.slice(0, 5)) {
        leaked.push(`env:${key}`);
      }
    }
  }

  // Deduplicate, preserve order
  return [...new Map(leaked.map((v) => [v, v])).values()];
}

export class MemoTable {
  readonly entries: ConversationMemo[] = [];

  record(finding: Finding): void {
    this.entries.push({
      probeId: finding.probeId,
      category: finding.category,
      techniques: inferTechniques(finding),
      outcome: classifyOutcome(finding),
      verdict: finding.verdict,
      leakedInfo: extractLeakedInfo(finding),
    });
  }

  effectiveTechniques(category?: string): Map<Technique, number> {
    const counts = new Map<Technique, number>();
    for (const entry of this.entries) {
      if (category && entry.category !== category) continue;
      if (entry.verdict !== Verdict.Vulnerable) continue;
      for (const tech of entry.techniques) {
        counts.set(tech, (counts.get(tech) ?? 0) + 1);
      }
    }
    return new Map([...counts.entries()].sort((a, b) => b[1] - a[1]));
  }

  promisingTechniques(category?: string): Map<Technique, number> {
    const scores = new Map<Technique, number>();
    for (const entry of this.entries) {
      if (category && entry.category !== category) continue;
      const weight = entry.verdict === Verdict.Vulnerable ? 1.0 : entry.verdict === Verdict.Inconclusive ? 0.3 : 0;
      if (weight === 0) continue;
      for (const tech of entry.techniques) {
        scores.set(tech, (scores.get(tech) ?? 0) + weight);
      }
    }
    return new Map([...scores.entries()].sort((a, b) => b[1] - a[1]));
  }

  deadEndTechniques(category?: string): Map<Technique, number> {
    const vulnTechniques = new Set<Technique>();
    const safeCounts = new Map<Technique, number>();

    for (const entry of this.entries) {
      if (category && entry.category !== category) continue;
      for (const tech of entry.techniques) {
        if (entry.verdict === Verdict.Vulnerable) {
          vulnTechniques.add(tech);
        } else if (entry.verdict === Verdict.Safe) {
          safeCounts.set(tech, (safeCounts.get(tech) ?? 0) + 1);
        }
      }
    }

    const result = new Map<Technique, number>();
    for (const [tech, count] of [...safeCounts.entries()].sort((a, b) => b[1] - a[1])) {
      if (!vulnTechniques.has(tech)) {
        result.set(tech, count);
      }
    }
    return result;
  }

  allLeakedInfo(): string[] {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const entry of this.entries) {
      for (const info of entry.leakedInfo) {
        if (!seen.has(info)) {
          seen.add(info);
          result.push(info);
        }
      }
    }
    return result;
  }

  categorySuccessRate(category: string): number {
    const relevant = this.entries.filter((e) => e.category === category);
    if (relevant.length === 0) return 0;
    return relevant.filter((e) => e.verdict === Verdict.Vulnerable).length / relevant.length;
  }

  scoreProbeTechniques(techniques: Technique[], category: string): number {
    const promising = this.promisingTechniques(category);
    const deadEnds = this.deadEndTechniques(category);
    const globalPromising = this.promisingTechniques();

    let score = 0;
    for (const tech of techniques) {
      const promScore = promising.get(tech);
      const globalScore = globalPromising.get(tech);
      const deadScore = deadEnds.get(tech);

      if (promScore !== undefined) {
        score += promScore * 2.0;
      } else if (globalScore !== undefined) {
        score += globalScore * 0.5;
      }
      if (deadScore !== undefined) {
        score -= deadScore * 1.0;
      }
    }
    return score;
  }
}
