import { z } from 'zod';

const BASE = import.meta.env.VITE_API_BASE_URL || '';

export const ScanCreateResponse = z.object({
  scan_id: z.string(),
  status: z.string(),
  reported_financial_loss: z.boolean(),
});

/** Evidence is stored as either a keyed record or a list of evidence entries. */
const Evidence = z.union([z.record(z.string(), z.unknown()), z.array(z.unknown())]);

export const ScanDetail = z.object({
  scan_id: z.string(),
  status: z.string(),
  reported_financial_loss: z.boolean(),
  classification: z.string().optional(),
  technical_evidence: Evidence.optional(),
  social_engineering_evidence: Evidence.optional(),
  confidence: z.string().optional(),
  rule_ids: z.array(z.string()).optional(),
  ruleset_version: z.string().optional(),
  explanation_key: z.string().optional(),
  disclaimer: z.string().optional(),
});

export type ScanDetail = z.infer<typeof ScanDetail>;

export async function createScan(
  content: string,
  lostMoney: boolean
): Promise<z.infer<typeof ScanCreateResponse>> {
  const res = await fetch(`${BASE}/api/v1/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Idempotency-Key': crypto.randomUUID() },
    body: JSON.stringify({
      raw_content: content,
      reported_financial_loss: lostMoney,
      channel: 'web',
    }),
  });
  if (!res.ok) throw new Error('submit_failed');
  return ScanCreateResponse.parse(await res.json());
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  const res = await fetch(`${BASE}/api/v1/scans/${scanId}`);
  if (!res.ok) throw new Error('not_found');
  return ScanDetail.parse(await res.json());
}

export async function deleteScan(scanId: string): Promise<void> {
  // Spec §6: DELETE /api/v1/scans/{scan_id}. A scan that is already gone is
  // treated as success so stale local history can always be cleaned up.
  const res = await fetch(`${BASE}/api/v1/scans/${scanId}`, { method: 'DELETE' });
  if (!res.ok && res.status !== 404) throw new Error('delete_failed');
}

export const ReportSignedUrl = z.object({
  url: z.string(),
  expires_in: z.number(),
});

export type ReportSignedUrl = z.infer<typeof ReportSignedUrl>;

/**
 * Step 1 of the PDF download: GET without a token mints a short-lived
 * signed URL (spec §6). Step 2 fetches that URL for the actual bytes.
 */
export async function getReportSignedUrl(scanId: string): Promise<ReportSignedUrl> {
  const res = await fetch(`${BASE}/api/v1/scans/${scanId}/report.pdf`);
  if (!res.ok) throw new Error('report_url_failed');
  return ReportSignedUrl.parse(await res.json());
}

export async function fetchReportPdf(signedUrl: string): Promise<Blob> {
  const res = await fetch(`${BASE}${signedUrl}`);
  if (!res.ok) throw new Error('report_failed');
  return res.blob();
}

export function defang(text: string): string {
  // Only rewrite a real scheme prefix: a blanket /http/g would also mangle
  // hostnames such as "httpbin.org". Bare domains (no scheme) still get
  // their dots bracketed.
  return text
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/\./g, '[.]');
}
