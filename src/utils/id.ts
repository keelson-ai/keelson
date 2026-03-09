import { randomBytes } from 'node:crypto';

function datePrefix(): string {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

function hexSuffix(): string {
  return randomBytes(3).toString('hex');
}

export function generateScanId(): string {
  return `scan-${datePrefix()}-${hexSuffix()}`;
}

export function generateCampaignId(): string {
  return `campaign-${datePrefix()}-${hexSuffix()}`;
}
