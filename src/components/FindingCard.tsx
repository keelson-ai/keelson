import React from 'react';
import { Box, Text } from 'ink';

import type { Finding } from '../types/index.js';
import { Severity, Verdict } from '../types/index.js';

export interface FindingCardProps {
  finding: Finding;
  index: number;
}

const VERDICT_ICON: Record<Verdict, { symbol: string; color: string }> = {
  [Verdict.Vulnerable]: { symbol: '\u2717', color: 'red' },
  [Verdict.Safe]: { symbol: '\u2713', color: 'green' },
  [Verdict.Inconclusive]: { symbol: '?', color: 'yellow' },
};

const SEVERITY_COLOR: Record<Severity, string> = {
  [Severity.Critical]: 'redBright',
  [Severity.High]: 'red',
  [Severity.Medium]: 'yellow',
  [Severity.Low]: 'gray',
};

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '...';
}

export function FindingCard({ finding, index }: FindingCardProps): React.ReactElement {
  const verdict = VERDICT_ICON[finding.verdict];
  const sevColor = SEVERITY_COLOR[finding.severity];
  const confidence = Math.round(finding.confidence * 100);

  return (
    <Box flexDirection="column" paddingLeft={1} marginBottom={1}>
      {/* Header: index, verdict icon, probe name, severity badge */}
      <Box gap={1}>
        <Text bold>#{index + 1}</Text>
        <Text color={verdict.color}>{verdict.symbol}</Text>
        <Text bold>{finding.probeName}</Text>
        <Text color={sevColor as never}>[{finding.severity}]</Text>
        <Text dimColor>({confidence}%)</Text>
      </Box>

      {/* Probe ID and category */}
      <Box gap={1} paddingLeft={2}>
        <Text dimColor>Probe:</Text>
        <Text>{finding.probeId}</Text>
        <Text dimColor>|</Text>
        <Text dimColor>Category:</Text>
        <Text>{finding.category}</Text>
        <Text dimColor>|</Text>
        <Text dimColor>OWASP:</Text>
        <Text>{finding.owaspId}</Text>
      </Box>

      {/* Reasoning */}
      {finding.reasoning && (
        <Box paddingLeft={2}>
          <Text dimColor>Reasoning: </Text>
          <Text>{truncate(finding.reasoning, 200)}</Text>
        </Box>
      )}

      {/* Evidence preview */}
      {finding.evidence.length > 0 && (
        <Box flexDirection="column" paddingLeft={2} marginTop={0}>
          <Text dimColor>Evidence (step {finding.evidence[0].stepIndex}):</Text>
          <Box paddingLeft={2} flexDirection="column">
            <Text>
              <Text dimColor>Prompt: </Text>
              {truncate(finding.evidence[0].prompt, 80)}
            </Text>
            <Text>
              <Text dimColor>Response: </Text>
              {truncate(finding.evidence[0].response, 80)}
            </Text>
          </Box>
        </Box>
      )}
    </Box>
  );
}
