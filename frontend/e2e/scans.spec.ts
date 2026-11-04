import { test, expect } from '@playwright/test';

test('submission to report flow (mocked API)', async ({ page }) => {
  await page.route('**/api/v1/scans', async (route) => {
    if (route.request().method() === 'POST') {
      await route.fulfill({
        json: { scan_id: 'test-123', status: 'PENDING', reported_financial_loss: false },
      });
    } else {
      await route.continue();
    }
  });
  await page.route('**/api/v1/scans/test-123', async (route) => {
    await route.fulfill({
      json: {
        scan_id: 'test-123',
        status: 'COMPLETED',
        reported_financial_loss: false,
        classification: 'SUSPICIOUS',
        confidence: 'MEDIUM',
        rule_ids: ['SE_URGENCY_EN'],
        explanation_key: 'assessment.suspicious',
        technical_evidence: {},
        social_engineering_evidence: {},
      },
    });
  });

  await page.goto('/');
  await page.getByPlaceholder(/suspicious/i).fill('Act now! https://evil.example/login');
  await page.getByLabel(/privacy notice/i).check();
  await page.getByRole('button', { name: /check/i }).click();
  await expect(page).toHaveURL(/\/scan\/test-123/);
  await expect(page.getByText(/Signals warrant caution/i)).toBeVisible({ timeout: 10000 });
});
