import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import HistoryPage from './HistoryPage';

const deleteScan = vi.fn().mockResolvedValue(undefined);

vi.mock('../../shared/api', () => ({
  deleteScan: (...args: unknown[]) => deleteScan(...args),
}));

function renderWith(items: { scan_id: string; status: string }[]) {
  localStorage.setItem('cybersathi-history', JSON.stringify(items));
  return render(
    <MemoryRouter>
      <HistoryPage />
    </MemoryRouter>
  );
}

describe('HistoryPage', () => {
  beforeEach(() => {
    localStorage.clear();
    deleteScan.mockClear();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  it('shows empty state when no scans', () => {
    renderWith([]);
    expect(screen.getByText('No scans yet.')).toBeDefined();
  });

  it('lists stored scans (IDs only, never raw content)', () => {
    renderWith([
      { scan_id: '11111111-2222-3333-4444-555555555555', status: 'COMPLETED' },
      { scan_id: '66666666-7777-8888-9999-000000000000', status: 'RUNNING' },
    ]);
    expect(screen.getByText(/11111111… · COMPLETED/)).toBeDefined();
    expect(screen.getByText(/66666666… · RUNNING/)).toBeDefined();
  });

  it('deletes a scan on confirm and updates storage', async () => {
    renderWith([{ scan_id: '11111111-2222-3333-4444-555555555555', status: 'COMPLETED' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('No scans yet.')).toBeDefined();
    expect(deleteScan).toHaveBeenCalledWith('11111111-2222-3333-4444-555555555555');
    expect(JSON.parse(localStorage.getItem('cybersathi-history') || '[]')).toHaveLength(0);
  });

  it('keeps the scan when delete is cancelled', () => {
    (window.confirm as ReturnType<typeof vi.fn>).mockReturnValue(false);
    renderWith([{ scan_id: '11111111-2222-3333-4444-555555555555', status: 'COMPLETED' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(deleteScan).not.toHaveBeenCalled();
    expect(screen.getByText(/11111111… · COMPLETED/)).toBeDefined();
  });
});
