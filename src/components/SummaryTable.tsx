import React from 'react';
import { Box, Text } from 'ink';

import type { ScanSummary } from '../types/index.js';
import { Severity } from '../types/index.js';

export interface SummaryTableProps {
  summary: ScanSummary;
}

const SEVERITY_COLOR: Record<Severity, string> = {
  [Severity.Critical]: 'redBright',
  [Severity.High]: 'red',
  [Severity.Medium]: 'yellow',
  [Severity.Low]: 'gray',
};

function SeverityRow({
  severity,
  count,
}: {
  severity: Severity;
  count: number;
}): React.ReactElement | null {
  if (count === 0) return null;
  return (
    <Box gap={1} paddingLeft={2}>
      <Text color={SEVERITY_COLOR[severity] as never}>
        {severity.padEnd(10)}
      </Text>
      <Text>{count}</Text>
    </Box>
  );
}

export function SummaryTable({ summary }: SummaryTableProps): React.ReactElement {
  const passed = summary.vulnerable === 0;
  const categoryEntries = Object.entries(summary.byCategory).filter(
    ([, count]) => count > 0,
  );

  return (
    <Box flexDirection="column" paddingLeft={1}>
      {/* Overall status */}
      <Box marginBottom={1}>
        {passed ? (
          <Text color="green" bold>
            {'\u2713'} PASS — No vulnerabilities found
          </Text>
        ) : (
          <Text color="red" bold>
            {'\u2717'} FAIL — {summary.vulnerable} vulnerability(ies) found
          </Text>
        )}
      </Box>

      {/* Verdict totals */}
      <Box gap={2}>
        <Text>Total: {summary.total}</Text>
        <Text color="red">Vulnerable: {summary.vulnerable}</Text>
        <Text color="green">Safe: {summary.safe}</Text>
        <Text color="yellow">Inconclusive: {summary.inconclusive}</Text>
      </Box>

      {/* Severity breakdown */}
      {summary.vulnerable > 0 && (
        <Box flexDirection="column" marginTop={1}>
          <Text bold>Vulnerabilities by Severity</Text>
          {[Severity.Critical, Severity.High, Severity.Medium, Severity.Low].map(
            (sev) => (
              <SeverityRow
                key={sev}
                severity={sev}
                count={summary.bySeverity[sev] ?? 0}
              />
            ),
          )}
        </Box>
      )}

      {/* Category breakdown */}
      {categoryEntries.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          <Text bold>Vulnerabilities by Category</Text>
          {categoryEntries.map(([cat, count]) => (
            <Box key={cat} gap={1} paddingLeft={2}>
              <Text>{cat.padEnd(30)}</Text>
              <Text color="red">{count}</Text>
            </Box>
          ))}
        </Box>
      )}
    </Box>
  );
}
