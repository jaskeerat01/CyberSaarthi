export type HistoryItem = {
  scan_id: string;
  status: string;
  /** ISO timestamp of the first time this scan was seen locally. */
  created?: string;
};

const STORAGE_KEY = 'cybersathi-history';
const MAX_ITEMS = 100;

function isHistoryItem(value: unknown): value is HistoryItem {
  if (!value || typeof value !== 'object') return false;
  const item = value as Record<string, unknown>;
  return typeof item.scan_id === 'string' && typeof item.status === 'string';
}

/**
 * Scan history is stored locally as IDs + status only — never raw content or
 * indicators. Storage may be unavailable (private mode, quota), so every
 * access is best-effort and falls back to an in-memory empty list.
 */
export function readHistory(): HistoryItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Strip anything except the known fields so older/buggy versions cannot
    // keep raw content or indicators in local history.
    return parsed
      .filter(isHistoryItem)
      .map((item) => ({
        scan_id: item.scan_id,
        status: item.status,
        ...(typeof item.created === 'string' ? { created: item.created } : {}),
      }))
      .slice(0, MAX_ITEMS);
  } catch {
    return [];
  }
}

export function writeHistory(items: HistoryItem[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(0, MAX_ITEMS)));
  } catch {
    /* storage unavailable — history is a convenience, not required data */
  }
}

/** Insert a new scan or update its status without changing its position. */
export function upsertHistory(scanId: string, status: string): void {
  if (!scanId) return;
  const items = readHistory();
  const existing = items.find((item) => item.scan_id === scanId);
  if (existing) {
    writeHistory(items.map((item) => (item.scan_id === scanId ? { ...item, status } : item)));
    return;
  }
  writeHistory([{ scan_id: scanId, status, created: new Date().toISOString() }, ...items]);
}

export function removeHistory(scanId: string): void {
  writeHistory(readHistory().filter((item) => item.scan_id !== scanId));
}
