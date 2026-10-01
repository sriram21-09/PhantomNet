import { test, expect } from '@playwright/test';

const VIEWPORTS = [
  { name: '1920x1080', width: 1920, height: 1080 },
  { name: '1440x900',  width: 1440, height: 900 },
  { name: '1366x768',  width: 1366, height: 768 },
  { name: '1024x768',  width: 1024, height: 768 },
  { name: '768x1024',  width: 768,  height: 1024 },
  { name: '480x900',   width: 480,  height: 900 },
  { name: '390x844',   width: 390,  height: 844 },
  { name: '360x800',   width: 360,  height: 800 },
];

test.describe('Network Topology Remediation & Verification Suite', () => {

  test('SEC-01: Unauthenticated request redirects to /login', async ({ page }) => {
    // Clear cookies
    await page.context().clearCookies();
    await page.goto('/topology');
    await expect(page).toHaveURL(/.*login/);
  });

  test('NT-01: Authenticated topology rendering, semantics, dynamic status, and ports', async ({ page }) => {
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
    await page.waitForURL('**/topology', { timeout: 10000 }).catch(async () => {
      await page.goto('/topology');
    });

    // 2. Verify Page Header & Semantics
    await expect(page.locator('.topology-title, h1, .header-title')).toContainText('Network Topology');
    await expect(page.locator('.topology-subtitle, .header-subtitle')).toContainText('Logical Deception Infrastructure');

    // 3. Verify Telemetry Sync Badge & Live Feed
    const syncBadge = page.locator('.telemetry-sync-badge');
    await expect(syncBadge).toBeVisible();
    await expect(syncBadge).toContainText('SYNCED');

    const liveBadge = page.locator('.live-feed-badge, .badge-live');
    await expect(liveBadge).toContainText('LIVE FEED ACTIVE');

    // 4. Verify Nodes (At least 5 nodes: Controller + 4 Honeypots)
    const nodes = page.locator('.react-flow__node');
    await expect(nodes).toHaveCount(5);

    // 5. Verify Controller Node (PHANTOM_OS - CORE CONTROLLER - ONLINE)
    const controller = page.locator('.react-flow__node-controller');
    await expect(controller).toBeVisible();
    await expect(controller).toContainText('PHANTOM_OS');
    await expect(controller).toContainText('CORE CONTROLLER');
    await expect(controller).toContainText('ONLINE');

    // 6. Verify Honeypot Port Semantics (Host Port → Container Port)
    const honeypotNodes = page.locator('.react-flow__node-honeypot');
    await expect(honeypotNodes).toHaveCount(4);

    // SSH: 2722 → 2222
    const sshNode = honeypotNodes.filter({ hasText: 'SSH' });
    await expect(sshNode).toBeVisible();
    await expect(sshNode).toContainText('PORT 2722 → 2222');
    await expect(sshNode).toContainText('ACTIVE');

    // HTTP: 8080 → 8080
    const httpNode = honeypotNodes.filter({ hasText: 'HTTP' });
    await expect(httpNode).toBeVisible();
    await expect(httpNode).toContainText('PORT 8080 → 8080');

    // FTP: 2721 → 2121
    const ftpNode = honeypotNodes.filter({ hasText: 'FTP' });
    await expect(ftpNode).toBeVisible();
    await expect(ftpNode).toContainText('PORT 2721 → 2121');

    // SMTP: 2725 → 2525
    const smtpNode = honeypotNodes.filter({ hasText: 'SMTP' });
    await expect(smtpNode).toBeVisible();
    await expect(smtpNode).toContainText('PORT 2725 → 2525');

    // 7. Verify Details Panel on Node Click
    await sshNode.click();
    const detailsPanel = page.locator('.node-details-panel');
    await expect(detailsPanel).toBeVisible();
    await expect(detailsPanel).toContainText('Host Port');
    await expect(detailsPanel).toContainText('2722');
    await expect(detailsPanel).toContainText('Container Port');
    await expect(detailsPanel).toContainText('2222');
    await expect(detailsPanel).toContainText('Logical Control Plane Link');

    // 8. Close details panel
    await page.locator('.panel-close-btn').click();
    await expect(detailsPanel).not.toBeVisible();

    // Verify zero fatal console errors
    const fatalErrors = consoleErrors.filter(e => !e.includes('favicon') && !e.includes('DevTools'));
    expect(fatalErrors).toHaveLength(0);
  });

  for (const vp of VIEWPORTS) {
    test(`RESPONSIVE: Viewport ${vp.name} (${vp.width}x${vp.height}) usability and layout`, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height });

      // Login
      await page.goto('/login');
      await page.fill('input[name="username"], input[type="text"]', 'admin');
      await page.fill('input[name="password"], input[type="password"]', 'PhantomNet_SecAdmin_2026!');
      await page.click('button[type="submit"]');
      await page.waitForURL('**/topology', { timeout: 10000 }).catch(async () => {
        await page.goto('/topology');
      });

      await page.waitForSelector('.react-flow__node');

      // Check no horizontal body overflow
      const hasHorizontalOverflow = await page.evaluate(() => {
        return document.documentElement.scrollWidth > window.innerWidth;
      });
      expect(hasHorizontalOverflow).toBe(false);

      // Open details panel and verify it stays bounded within viewport
      const sshNode = page.locator('.react-flow__node-honeypot').first();
      await sshNode.click();
      const detailsPanel = page.locator('.node-details-panel');
      await expect(detailsPanel).toBeVisible();

      const panelBox = await detailsPanel.boundingBox();
      expect(panelBox).not.toBeNull();
      if (panelBox) {
        expect(panelBox.x).toBeGreaterThanOrEqual(0);
        expect(panelBox.x + panelBox.width).toBeLessThanOrEqual(vp.width + 10);
      }
    });
  }

});
