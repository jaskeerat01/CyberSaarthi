import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ResultPage from './ResultPage';

vi.mock('../../shared/api', () => ({
  getScan: vi.fn().mockResolvedValue({
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
  }),
}));

function wrap() {
  return render(
    <MemoryRouter initialEntries={['/scan/abc/result']}>
      <QueryClientProvider client={new QueryClient()}>
        <Routes>
          <Route path="/scan/:scanId/result" element={<ResultPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe('ResultPage', () => {
  it('renders success state', async () => {
    wrap();
    expect(await screen.findByText(/Signals warrant caution/i)).toBeDefined();
  });

  it('shows disclaimer', async () => {
    wrap();
    expect(await screen.findByText(/not a guarantee/i)).toBeDefined();
  });
});
