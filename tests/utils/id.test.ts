import { describe, expect, it } from 'vitest';

import { generateCampaignId, generateScanId } from '../../src/utils/id.js';

describe('generateScanId', () => {
  it('matches format scan-YYYY-MM-DD-<6hex>', () => {
    const id = generateScanId();
    expect(id).toMatch(/^scan-\d{4}-\d{2}-\d{2}-[0-9a-f]{6}$/);
  });

  it('generates unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateScanId()));
    expect(ids.size).toBe(100);
  });
});

describe('generateCampaignId', () => {
  it('matches format campaign-YYYY-MM-DD-<6hex>', () => {
    const id = generateCampaignId();
    expect(id).toMatch(/^campaign-\d{4}-\d{2}-\d{2}-[0-9a-f]{6}$/);
  });
});
