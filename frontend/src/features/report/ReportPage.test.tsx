import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ReportPage from './ReportPage';

const getScan = vi.fn();
const getReportSignedUrl = vi.fn();
const fetchReportPdf = vi.fn();

vi.mock('../../shared/api', () => ({
  getScan: (...args: unknown[]) => getScan(...args),
  getReportSignedUrl: (...args: unknown[]) => getReportSignedUrl(...args),
  fetchReportPdf: (...args: unknown[]) => fetchReportPdf(...args),
}));

function wrap() {
  return render(
    <MemoryRouter initialEntries={['/scan/abc/report']}>
      <QueryClientProvider client={new QueryClient()}>
        <Routes>
          <Route path="/scan/:scanId/report" element={<ReportPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe('ReportPage (signed-URL two-step download)', () => {
  beforeEach(() => {
    getScan.mockReset();
    getReportSignedUrl.mockReset();
    fetchReportPdf.mockReset();
    window.URL.createObjectURL = vi.fn(() => 'blob:mock') as typeof URL.createObjectURL;
    window.URL.revokeObjectURL = vi.fn() as typeof URL.revokeObjectURL;
  });

  it('renders report title and preparation-aid note', async () => {
    getScan.mockResolvedValue({
      scan_id: 'abc',
      status: 'COMPLETED',
      reported_financial_loss: false,
    });
    wrap();
    expect(await screen.findByText(/Complaint Preparation Report/)).toBeDefined();
    expect(screen.getByText(/preparation aid/i)).toBeDefined();
  });

  it('mints a signed URL then fetches the PDF through it', async () => {
    getScan.mockResolvedValue({
      scan_id: 'abc',
      status: 'COMPLETED',
      reported_financial_loss: false,
    });
    getReportSignedUrl.mockResolvedValue({
      url: '/api/v1/scans/abc/report.pdf?token=x',
      expires_in: 900,
    });
    fetchReportPdf.mockResolvedValue(new Blob(['pdf-bytes']));
    wrap();
    const button = await screen.findByRole('button', { name: /Download PDF/i });
    await waitFor(() => expect(button).not.toBeDisabled());
    fireEvent.click(button);
    await waitFor(() =>
      expect(fetchReportPdf).toHaveBeenCalledWith('/api/v1/scans/abc/report.pdf?token=x')
    );
    // Step 1 happened before step 2
    expect(getReportSignedUrl).toHaveBeenCalledWith('abc');
    expect(getReportSignedUrl.mock.invocationCallOrder[0]).toBeLessThan(
      fetchReportPdf.mock.invocationCallOrder[0]
    );
  });

  it('shows error message when the signed URL cannot be minted', async () => {
    getScan.mockResolvedValue({
      scan_id: 'abc',
      status: 'COMPLETED',
      reported_financial_loss: false,
    });
    getReportSignedUrl.mockRejectedValue(new Error('report_url_failed'));
    wrap();
    const button = await screen.findByRole('button', { name: /Download PDF/i });
    await waitFor(() => expect(button).not.toBeDisabled());
    fireEvent.click(button);
    expect(await screen.findByRole('alert')).toHaveTextContent(/Something went wrong/i);
  });

  it('shows 1930 helpline when financial loss was reported', async () => {
    getScan.mockResolvedValue({
      scan_id: 'abc',
      status: 'COMPLETED',
      reported_financial_loss: true,
    });
    wrap();
    expect(await screen.findByText('1930')).toBeDefined();
  });
});
