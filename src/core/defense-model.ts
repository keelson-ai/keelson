import { containsRefusal, isHardRefusal } from './detection.js';
import { inferTechniques } from './memo.js';
import type { DefenseProfile, FilterPattern, Finding, ProbeTemplate } from '../types/index.js';
import { Verdict } from '../types/index.js';

const MIN_OBSERVATIONS = 5;

const STOP_WORDS = new Set([
  'the',
  'and',
  'for',
  'are',
  'but',
  'not',
  'you',
  'all',
  'can',
  'her',
  'was',
  'one',
  'our',
  'out',
  'this',
  'that',
  'with',
  'have',
  'from',
  'your',
  'they',
  'will',
  'what',
  'when',
  'make',
  'like',
  'just',
  'over',
  'such',
  'take',
  'than',
  'them',
  'very',
  'some',
  'could',
  'would',
  'about',
  'which',
  'into',
  'their',
  'been',
  'said',
  'each',
  'also',
  'should',
  'please',
  'help',
  'here',
  'there',
]);

interface Observation {
  probe: ProbeTemplate;
  finding: Finding;
}

function extractWords(probe: ProbeTemplate): string[] {
  const text = probe.turns
    .filter((t) => t.role === 'user')
    .map((t) => t.content)
    .join(' ')
    .toLowerCase();

  return text.split(/[^a-z]+/).filter((w) => w.length > 3 && !STOP_WORDS.has(w));
}

function getLastResponse(finding: Finding): string {
  const evidence = finding.evidence;
  return evidence.length > 0 ? evidence[evidence.length - 1].response : '';
}

export class DefenseModel {
  private observations: Observation[] = [];

  observe(probe: ProbeTemplate, finding: Finding): void {
    this.observations.push({ probe, finding });
  }

  getTriggerPatterns(): string[] {
    if (this.observations.length < MIN_OBSERVATIONS) return [];

    const refusals = this.observations.filter(
      (o) => o.finding.verdict === Verdict.Safe && containsRefusal(getLastResponse(o.finding)),
    );
    const vulns = this.observations.filter((o) => o.finding.verdict === Verdict.Vulnerable);

    if (refusals.length === 0) return [];

    const wordRefusalCount = new Map<string, number>();
    const wordVulnCount = new Map<string, number>();

    for (const obs of refusals) {
      const words = new Set(extractWords(obs.probe));
      for (const w of words) {
        wordRefusalCount.set(w, (wordRefusalCount.get(w) ?? 0) + 1);
      }
    }

    for (const obs of vulns) {
      const words = new Set(extractWords(obs.probe));
      for (const w of words) {
        wordVulnCount.set(w, (wordVulnCount.get(w) ?? 0) + 1);
      }
    }

    const triggers: string[] = [];
    for (const [word, refCount] of wordRefusalCount) {
      const refusalRate = refCount / refusals.length;
      const vulnCount = wordVulnCount.get(word) ?? 0;
      const vulnRate = vulns.length > 0 ? vulnCount / vulns.length : 0;

      if (refusalRate >= 0.7 && vulnRate < 0.3) {
        triggers.push(word);
      }
    }

    return triggers;
  }

  getSafeFramings(): string[] {
    if (this.observations.length < MIN_OBSERVATIONS) return [];

    const techniqueSet = new Set<string>();
    for (const obs of this.observations) {
      if (obs.finding.verdict !== Verdict.Vulnerable) continue;
      const techniques = inferTechniques(obs.finding);
      for (const t of techniques) {
        techniqueSet.add(t);
      }
    }

    return [...techniqueSet];
  }

  getUndefendedTopics(): string[] {
    if (this.observations.length < MIN_OBSERVATIONS) return [];

    const categoryStats = new Map<string, { total: number; vuln: number }>();
    for (const obs of this.observations) {
      const cat = obs.finding.category;
      const stats = categoryStats.get(cat) ?? { total: 0, vuln: 0 };
      stats.total++;
      if (obs.finding.verdict === Verdict.Vulnerable) stats.vuln++;
      categoryStats.set(cat, stats);
    }

    const undefended: string[] = [];
    for (const [cat, stats] of categoryStats) {
      if (stats.vuln / stats.total > 0.5) {
        undefended.push(cat);
      }
    }

    return undefended;
  }

  getFilterPatterns(): FilterPattern[] {
    if (this.observations.length < MIN_OBSERVATIONS) return [];

    const hardRefusals = this.observations.filter(
      (o) => o.finding.verdict === Verdict.Safe && isHardRefusal(getLastResponse(o.finding)),
    );

    if (hardRefusals.length === 0) return [];

    const wordProbeIds = new Map<string, Set<string>>();
    for (const obs of hardRefusals) {
      const words = new Set(extractWords(obs.probe));
      for (const w of words) {
        if (!wordProbeIds.has(w)) wordProbeIds.set(w, new Set());
        const ids = wordProbeIds.get(w);
        if (ids) ids.add(obs.probe.id);
      }
    }

    const patterns: FilterPattern[] = [];
    for (const [word, probeIds] of wordProbeIds) {
      if (probeIds.size === hardRefusals.length) {
        patterns.push({
          trigger: word,
          confidence: 1.0,
          evidence: [...probeIds],
        });
      }
    }

    return patterns;
  }

  getDefenseProfile(): DefenseProfile {
    if (this.observations.length < MIN_OBSERVATIONS) {
      return {
        triggerWords: [],
        safeFramings: [],
        undefendedTopics: [],
        filterPatterns: [],
        defenseStrength: 0,
        refusalStyle: 'unknown',
      };
    }

    const vulnCount = this.observations.filter((o) => o.finding.verdict === Verdict.Vulnerable).length;
    const defenseStrength = 1 - vulnCount / this.observations.length;

    return {
      triggerWords: this.getTriggerPatterns(),
      safeFramings: this.getSafeFramings(),
      undefendedTopics: this.getUndefendedTopics(),
      filterPatterns: this.getFilterPatterns(),
      defenseStrength,
      refusalStyle: this.classifyRefusalStyle(),
    };
  }

  private classifyRefusalStyle(): DefenseProfile['refusalStyle'] {
    const refusalObs = this.observations.filter(
      (o) => o.finding.verdict === Verdict.Safe && containsRefusal(getLastResponse(o.finding)),
    );

    if (refusalObs.length === 0) return 'unknown';

    let hardCount = 0;
    let leakyCount = 0;

    for (const obs of refusalObs) {
      const response = getLastResponse(obs.finding);
      if (isHardRefusal(response)) {
        hardCount++;
      }
      // Leaky: contains refusal but also has evidence of leakage signals
      if (obs.finding.leakageSignals.length > 0) {
        leakyCount++;
      }
    }

    if (leakyCount > 0) return 'leaky';
    if (hardCount === refusalObs.length) return 'rigid';
    if (hardCount === 0) return 'polite';
    return 'inconsistent';
  }
}
