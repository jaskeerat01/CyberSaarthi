import { describe, it, expect, vi, afterEach } from 'vitest';
import { defang, deleteScan } from './api';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('defang', () => {
  it('defangs URLs', () => {
    expect(defang('https://evil.example.com/login')).toBe('hxxps://evil[.]example[.]com/login');
  });
});

describe('deleteScan', () => {
  it('treats an already-deleted scan (404) as success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404 }));
    await expect(deleteScan('abc')).resolves.toBeUndefined();
  });

  it('throws when deletion fails for another reason', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    await expect(deleteScan('abc')).rejects.toThrow('delete_failed');
  });
});
