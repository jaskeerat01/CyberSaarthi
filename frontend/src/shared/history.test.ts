import { describe, it, expect, beforeEach } from 'vitest';
import { readHistory, removeHistory, upsertHistory, writeHistory } from './history';

describe('scan history storage', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns an empty list when nothing is stored', () => {
    expect(readHistory()).toEqual([]);
  });

  it('ignores corrupt JSON and non-array payloads', () => {
    localStorage.setItem('cybersathi-history', '{not json');
    expect(readHistory()).toEqual([]);
    localStorage.setItem('cybersathi-history', '{"scan_id":"abc"}');
    expect(readHistory()).toEqual([]);
  });

  it('keeps only scan id, status and created timestamp', () => {
    localStorage.setItem(
      'cybersathi-history',
      JSON.stringify([
        {
          scan_id: 'abc',
          status: 'RUNNING',
          created: '2026-01-01T00:00:00.000Z',
          raw_content: 'secret message',
          domains: ['evil.example'],
        },
      ])
    );
    expect(readHistory()).toEqual([
      { scan_id: 'abc', status: 'RUNNING', created: '2026-01-01T00:00:00.000Z' },
    ]);
  });

  it('adds new scans at the front and updates existing ones in place', () => {
    upsertHistory('first', 'PENDING');
    upsertHistory('second', 'RUNNING');
    upsertHistory('first', 'COMPLETED');

    const items = readHistory();
    expect(items.map((item) => [item.scan_id, item.status])).toEqual([
      ['second', 'RUNNING'],
      ['first', 'COMPLETED'],
    ]);
  });

  it('removes an entry', () => {
    writeHistory([{ scan_id: 'abc', status: 'COMPLETED' }]);
    removeHistory('abc');
    expect(readHistory()).toEqual([]);
  });
});
