import { test, expect } from '@playwright/test';

test.describe('Neural Operations Center (NOC) Remediation E2E Suite', () => {

  test('NOC-SEC-01: Unauthenticated request redirects to /login', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('/advanced-dashboard');
    await expect(page).toHaveURL(/.*login/);
  });

  test('NOC-E2E-02: Authenticated NOC lifecycle, telemetry, attribution, and truthful prediction', async ({ page }) => {
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // 1. Login
    await page.goto('/login');
    await page.fill('input[name="username"], input[type="text"]', 'admin');
    await page.fill('input[name="password"], input[type="password"]', 'PhantomNet_SecAdmin_2026!');
    await page.click('button[type="submit"]');

    // 2. Navigate to /advanced-dashboard
    await page.goto('/advanced-dashboard');

    // 3. Verify Page Title & Truthful Subtitle
    await expect(page.locator('.dashboard-title')).toContainText('Neural Operations Center');
    await expect(page.locator('.dashboard-subtitle')).toContainText('REAL-TIME THREAT TELEMETRY | STATISTICAL THREAT FORECASTING');

    // 4. Verify Single Connection Banner
    const banner = page.locator('.connection-banner');
    await expect(banner).toBeVisible();

    // 5. Verify Live Metrics Grid
    const liveMetrics = page.locator('.live-metrics-grid');
    await expect(liveMetrics).toBeVisible();

    // 6. Verify Predictive Analytics Panel
    const predPanel = page.locator('.predictive-container');
    await expect(predPanel).toBeVisible();
    // Must NOT contain false LSTM-V3 claim
    await expect(page.locator('.engine-status')).not.toContainText('LSTM-V3');
    await expect(page.locator('.engine-status')).toContainText('STATISTICAL FORECAST');

    // 7. Verify Attack Attribution Panel
    const attrPanel = page.locator('.attribution-container');
    await expect(attrPanel).toBeVisible();
    await expect(attrPanel.locator('.attribution-header')).toContainText('ATTACK ATTRIBUTION');
    // Must have truthful evidence source
    await expect(attrPanel.locator('.attribution-footer')).toContainText('Source: Database');

    // 8. Verify Event Stream Panel
    const streamPanel = page.locator('.event-stream-container');
    await expect(streamPanel).toBeVisible();
    await expect(streamPanel.locator('.event-stream-header')).toContainText('LIVE EVENT STREAM');

    // 9. Verify No Console Errors Expose Secrets or Failures
    expect(consoleErrors.filter(e => !e.includes('favicon') && !e.includes('AudioContext'))).toHaveLength(0);
  });

  test('NOC-SEC-03: Protected NOC APIs strictly reject unauthenticated HTTP requests', async ({ request }) => {
    const endpoints = [
      '/api/v1/predictive/forecast',
      '/api/v1/predictive/risk-score',
      '/api/v1/predictive/next-attack',
      '/api/v1/attribution/top-attackers',
      '/api/v1/attribution/profile/10.99.1.100',
    ];

    for (const ep of endpoints) {
      const res = await request.get(ep);
      expect(res.status()).toBe(401);
    }
  });

});
