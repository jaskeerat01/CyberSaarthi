import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ResultPage from '../features/report/ResultPage';
import SubmissionPage from '../features/submission/SubmissionPage';
import { seriousViolations } from './a11y';

vi.mock('../shared/api', () => ({
  getScan: vi.fn().mockResolvedValue({
    scan_id: 'abc',
    status: 'COMPLETED',
    reported_financial_loss: true, // includes the helpline banner in the tree
    classification: 'NO_KNOWN_THREAT_DETECTED',
    confidence: 'MEDIUM',
    rule_ids: ['TECH_URL_PRESENT'],
    ruleset_version: '1.0',
    disclaimer: 'NO_KNOWN_THREAT_DETECTED does not guarantee safety or legitimacy.',
    technical_evidence: [{ domains: ['suspicious.example'] }],
    social_engineering_evidence: [],
  }),
  createScan: vi.fn(),
  defang: (text: string) => text,
}));

describe('accessibility (axe)', () => {
  beforeEach(() => {
    localStorage.clear(); // returns undefined — never return functions from hooks (vitest runs them as cleanups)
  });

  it('SubmissionPage has no serious violations', async () => {
    const { container } = render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <QueryClientProvider client={new QueryClient()}>
          <SubmissionPage />
        </QueryClientProvider>
      </MemoryRouter>
    );
    expect(await seriousViolations(container)).toEqual([]);
  });

  it('ResultPage (incl. helpline banner + defanged indicators) has no serious violations', async () => {
    const { container } = render(
      <MemoryRouter
        initialEntries={['/scan/abc/result']}
        future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      >
        <QueryClientProvider client={new QueryClient()}>
          <Routes>
            <Route path="/scan/:scanId/result" element={<ResultPage />} />
          </Routes>
        </QueryClientProvider>
      </MemoryRouter>
    );
    await screen.findByText(/Extracted indicators/);
    expect(await seriousViolations(container)).toEqual([]);
  });
});
