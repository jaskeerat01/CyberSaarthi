import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import SubmissionPage from './SubmissionPage';

vi.mock('../../shared/api', () => ({
  createScan: vi.fn(),
}));

function wrap() {
  return render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient()}>
        <SubmissionPage />
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe('SubmissionPage', () => {
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
});
