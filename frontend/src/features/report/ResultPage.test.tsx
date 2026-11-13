import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ResultPage from './ResultPage';
import { getScan } from '../../shared/api';

const mockScan = {
  scan_id: 'abc',
  status: 'COMPLETED',
  reported_financial_loss: false,
  classification: 'SUSPICIOUS',
  confidence: 'MEDIUM',
  rule_ids: ['SE_URGENCY_EN'],
  ruleset_version: '1.0',
  explanation_key: 'assessment.suspicious',
  technical_evidence: {},
  social_engineering_evidence: {},
};

vi.mock('../../shared/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../shared/api')>();
  return { ...actual, getScan: vi.fn() };
});

const mockedGetScan = vi.mocked(getScan);

function wrap() {
  return render(
    <MemoryRouter initialEntries={['/scan/abc/result']}>
      <QueryClientProvider client={new QueryClient()}>
        <Routes>
          <Route path="/scan/:scanId/result" element={<ResultPage />} />
          <Route path="/scan/:scanId" element={<p>status-page</p>} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe('ResultPage', () => {
  beforeEach(() => {
    mockedGetScan.mockReset();
    mockedGetScan.mockResolvedValue(mockScan);
  });

  it('renders success state', async () => {
    wrap();
    expect(await screen.findByText(/Signals warrant caution/i)).toBeDefined();
  });

  it('shows disclaimer', async () => {
    wrap();
    expect(await screen.findByText(/not a guarantee/i)).toBeDefined();
  });

  it('unwraps evidence items and defangs extracted domains', async () => {
    mockedGetScan.mockResolvedValue({
      ...mockScan,
      technical_evidence: { items: [{ domains: ['evil.example'] }] },
    });
    wrap();
    expect(await screen.findByText('evil[.]example')).toBeDefined();
    expect(screen.queryByText('https://evil.example')).toBeNull();
  });

  it('does not render raw domains anywhere, including the evidence dump', async () => {
    mockedGetScan.mockResolvedValue({
      ...mockScan,
      technical_evidence: {
        items: [{ domains: ['evil.example'] }, { provider: 'phishtank', outcome: 'MATCH' }],
      },
    });
    const { container } = wrap();
    await screen.findByText('evil[.]example');
    // The raw JSON evidence block must not contain the copy-pasteable domain.
    expect(container.textContent).not.toContain('"evil.example"');
  });

  it('redirects to the status page while the scan is not complete', async () => {
    mockedGetScan.mockResolvedValue({ ...mockScan, status: 'RUNNING' });
    wrap();
    expect(await screen.findByText('status-page')).toBeDefined();
  });
});
