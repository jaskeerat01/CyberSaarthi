import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import SubmissionPage from './SubmissionPage';
import { createScan } from '../../shared/api';

vi.mock('../../shared/api', () => ({
  createScan: vi.fn(),
}));

const mockedCreateScan = vi.mocked(createScan);

function wrap() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <QueryClientProvider client={new QueryClient()}>
        <SubmissionPage />
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe('SubmissionPage', () => {
  beforeEach(() => {
    localStorage.clear();
    mockedCreateScan.mockReset();
  });

  it('renders loading state (form)', () => {
    wrap();
    expect(screen.getByPlaceholderText(/suspicious/i)).toBeDefined();
  });

  it('shows 1930 banner when lost money checked', async () => {
    wrap();
    const checkbox = screen.getByLabelText(/lost money/i);
    fireEvent.click(checkbox);
    expect(screen.getAllByText(/1930/).length).toBeGreaterThan(0);
  });

  it('shows validation error without ack', async () => {
    wrap();
    const button = screen.getByRole('button', { name: /Check now/i });
    fireEvent.click(button);
    expect(await screen.findByRole('alert')).toBeDefined();
  });

  it('stores the new scan id and status in local history', async () => {
    mockedCreateScan.mockResolvedValue({
      scan_id: '11111111-2222-3333-4444-555555555555',
      status: 'PENDING',
      reported_financial_loss: false,
    });
    wrap();
    fireEvent.change(screen.getByPlaceholderText(/suspicious/i), {
      target: { value: 'Suspicious message' },
    });
    fireEvent.click(screen.getByLabelText(/privacy notice/i));
    fireEvent.click(screen.getByRole('button', { name: /Check now/i }));

    await waitFor(() => expect(mockedCreateScan).toHaveBeenCalledTimes(1));
    expect(JSON.parse(localStorage.getItem('cybersathi-history') || '[]')).toEqual([
      expect.objectContaining({
        scan_id: '11111111-2222-3333-4444-555555555555',
        status: 'PENDING',
      }),
    ]);
  });
});
