import React, { useEffect, useState } from 'react';
import { Box, Text } from 'ink';

import { Verdict } from '../types/index.js';

export interface ScanProgressProps {
  current: number;
  total: number;
  currentProbe?: string;
  findings: { vulnerable: number; safe: number; inconclusive: number };
}

const BAR_WIDTH = 30;

function formatElapsed(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (mins > 0) {
    return `${mins}m ${secs}s`;
  }
  return `${secs}s`;
}

function ProgressBar({ current, total }: { current: number; total: number }): React.ReactElement {
  const ratio = total > 0 ? current / total : 0;
  const filled = Math.round(ratio * BAR_WIDTH);
  const empty = BAR_WIDTH - filled;

  const filledStr = '\u2588'.repeat(filled);
  const emptyStr = '\u2591'.repeat(empty);
  const percentage = Math.round(ratio * 100);

  return (
    <Text>
      [{filledStr}{emptyStr}] {current}/{total} ({percentage}%)
    </Text>
  );
}

export function ScanProgress({
  current,
  total,
  currentProbe,
  findings,
}: ScanProgressProps): React.ReactElement {
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Box flexDirection="column" paddingLeft={1}>
      <Box marginBottom={1}>
        <Text bold>Keelson Security Scan</Text>
      </Box>

      <Box>
        <ProgressBar current={current} total={total} />
        <Text> </Text>
        <Text dimColor>{formatElapsed(elapsedSeconds)}</Text>
      </Box>

      {currentProbe && (
        <Box marginTop={0}>
          <Text dimColor>Current: </Text>
          <Text>{currentProbe}</Text>
        </Box>
      )}

      <Box marginTop={1} gap={2}>
        <Text color="red">
          {'\u2717'} Vulnerable: {findings.vulnerable}
        </Text>
        <Text color="green">
          {'\u2713'} Safe: {findings.safe}
        </Text>
        <Text color="yellow">
          ? Inconclusive: {findings.inconclusive}
        </Text>
      </Box>
    </Box>
  );
}
