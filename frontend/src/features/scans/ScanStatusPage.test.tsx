import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { act, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ScanStatusPage from './ScanStatusPage';

type Scan = { scan_id: string; status: string; reported_financial_loss: boolean };

const getScan = vi.fn();

vi.mock('../../shared/api', () => ({
  getScan: (...args: unknown[]) => getScan(...args),
}));

function wrap() {
  return render(
    <MemoryRouter initialEntries={['/scan/abc']}>
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <Routes>
          <Route path="/scan/:scanId" element={<ScanStatusPage />} />
          <Route path="/scan/:scanId/result" element={<p>result-page</p>} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe('ScanStatusPage', () => {
  beforeEach(() => {
    localStorage.clear();
    // NOTE: block body is deliberate — vitest invokes hook RETURN VALUES as
    // post-test cleanups, so an expression body returning the mock stub would
    // call the (rejecting) implementation again after the test.
    getScan.mockReset();
  });

  it('shows pending state while loading', async () => {
    // Hold the query in flight, then settle it before the test ends so the
    // query cache has no dangling in-flight promise (vitest teardown waits).
    let resolve!: (value: Scan) => void;
    getScan.mockReturnValue(new Promise<Scan>((res) => (resolve = res)));
    wrap();
    expect(screen.getByText(/Scan pending/i)).toBeDefined();
    await act(async () => {
      resolve({ scan_id: 'abc', status: 'PENDING', reported_financial_loss: false });
    });
  });

  it('renders stage list for a running scan', async () => {
    getScan.mockResolvedValue({
      scan_id: 'abc',
      status: 'RUNNING',
      reported_financial_loss: false,
    });
    wrap();
    expect(await screen.findByRole('heading', { name: 'Analysing…' })).toBeDefined();
    expect(screen.getByText('RUNNING')).toBeDefined();
  });

  it('records the latest status in local history', async () => {
    getScan.mockResolvedValue({
      scan_id: 'abc',
      status: 'RUNNING',
      reported_financial_loss: false,
    });
    wrap();
    await screen.findByRole('heading', { name: 'Analysing…' });
    await waitFor(() =>
      expect(JSON.parse(localStorage.getItem('cybersathi-history') || '[]')).toEqual([
        expect.objectContaining({ scan_id: 'abc', status: 'RUNNING' }),
      ])
    );
  });

  it('shows 1930 helpline immediately when financial loss reported', async () => {
    getScan.mockResolvedValue({
      scan_id: 'abc',
      status: 'PENDING',
      reported_financial_loss: true,
    });
    wrap();
    expect(await screen.findByText('1930')).toBeDefined();
  });

  it('shows error state on failure', async () => {
    // Reject eagerly; the no-op catch keeps the rejection "handled" from
    // creation so only react-query's own processing observes it.
    getScan.mockImplementation(() => {
      const p = Promise.reject(new Error('not_found'));
      void p.catch(() => undefined);
      return p;
    });
    wrap();
    const el = await screen.findByRole('alert');
    expect(el).toHaveTextContent(/Something went wrong/i);
  });
});
