import { Box, Text } from 'ink';
import React from 'react';

import { FindingCard } from './FindingCard.js';
import { SummaryTable } from './SummaryTable.js';
import type { ScanResult } from '../types/index.js';
import { Verdict } from '../types/index.js';

export interface ReportViewProps {
  result: ScanResult;
}

export function ReportView({ result }: ReportViewProps): React.ReactElement {
  const vulnFindings = result.findings.filter((f) => f.verdict === Verdict.Vulnerable);

  return (
    <Box flexDirection="column">
      {/* Header */}
      <Box flexDirection="column" paddingLeft={1} marginBottom={1}>
        <Text bold>Keelson Security Report</Text>
        <Box gap={1}>
          <Text dimColor>Target:</Text>
          <Text>{result.target}</Text>
        </Box>
        <Box gap={1}>
          <Text dimColor>Scan ID:</Text>
          <Text>{result.scanId}</Text>
        </Box>
        <Box gap={1}>
          <Text dimColor>Duration:</Text>
          <Text>
            {result.startedAt} → {result.completedAt}
          </Text>
        </Box>
      </Box>

      {/* Summary */}
      <SummaryTable summary={result.summary} />

      {/* Vulnerability details */}
      {vulnFindings.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          <Box paddingLeft={1} marginBottom={1}>
            <Text bold>Vulnerability Details</Text>
          </Box>
          {vulnFindings.map((f, i) => (
            <FindingCard key={f.probeId} finding={f} index={i} />
          ))}
        </Box>
      )}
    </Box>
  );
}
