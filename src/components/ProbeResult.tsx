import { Box, Text } from 'ink';
import React from 'react';

import { SEVERITY_COLOR, VERDICT_ICON } from './theme.js';
import { truncate } from '../cli/utils.js';
import type { Finding } from '../types/index.js';

export interface ProbeResultProps {
  finding: Finding;
  showEvidence?: boolean;
}

export function ProbeResult({ finding, showEvidence = true }: ProbeResultProps): React.ReactElement {
  const verdict = VERDICT_ICON[finding.verdict];
  const sevColor = SEVERITY_COLOR[finding.severity];

  return (
    <Box flexDirection="column" paddingLeft={1}>
      {/* Header */}
      <Box gap={1}>
        <Text color={verdict.color} bold>
          {verdict.symbol} {finding.verdict}
        </Text>
        <Text bold>
          {finding.probeId}: {finding.probeName}
        </Text>
      </Box>

      {/* Metadata */}
      <Box gap={1} paddingLeft={2} marginTop={0}>
        <Text dimColor>Severity:</Text>
        <Text color={sevColor as never}>{finding.severity}</Text>
        <Text dimColor>|</Text>
        <Text dimColor>Category:</Text>
        <Text>{finding.category}</Text>
        <Text dimColor>|</Text>
        <Text dimColor>OWASP:</Text>
        <Text>{finding.owaspId}</Text>
      </Box>

      {/* Confidence */}
      <Box paddingLeft={2}>
        <Text dimColor>Confidence: </Text>
        <Text>{Math.round(finding.confidence * 100)}%</Text>
      </Box>

      {/* Reasoning */}
      {finding.reasoning && (
        <Box paddingLeft={2}>
          <Text dimColor>Reasoning: </Text>
          <Text>{finding.reasoning}</Text>
        </Box>
      )}

      {/* Evidence */}
      {showEvidence && finding.evidence.length > 0 && (
        <Box flexDirection="column" paddingLeft={2} marginTop={1}>
          <Text dimColor bold>
            Evidence:
          </Text>
          {finding.evidence.map((ev, i) => (
            <Box key={i} flexDirection="column" paddingLeft={2}>
              <Text dimColor>Step {ev.stepIndex}:</Text>
              <Text>
                {' '}
                <Text dimColor>Prompt:</Text> {truncate(ev.prompt, 150)}
              </Text>
              <Text>
                {' '}
                <Text dimColor>Response:</Text> {truncate(ev.response, 200)}
              </Text>
            </Box>
          ))}
        </Box>
      )}
    </Box>
  );
}
