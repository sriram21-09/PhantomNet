import { test, expect } from '@playwright/test';

const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBZG1pbiIsImV4cCI6MTc5MTM4MTgwNn0.sMfONtOn0vn81EMl27A8kQWYhaNZvpMu2kbahWurPoU';

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

async function authenticateAndGoToTopology(page) {
  await page.context().addCookies([
    { name: 'phantomnet_access_token', value: TOKEN, url: 'http://127.0.0.1:3000' },
    { name: 'phantomnet_access_token', value: TOKEN, url: 'http://localhost:3000' },
  ]);
  await page.goto('http://127.0.0.1:3000/topology');
  await page.waitForSelector('.topology-container', { timeout: 30000 });
}

test.describe('Network Topology Remediation & Verification Suite', () => {

  test('SEC-01: Unauthenticated request redirects to /login', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('http://127.0.0.1:3000/topology');
    await expect(page).toHaveURL(/.*login/, { timeout: 15000 });
  });

  test('NT-01: Authenticated topology rendering, semantics, dynamic status, and ports', async ({ page }) => {
    page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()));
    page.on('requestfailed', req => console.log('REQ FAILED:', req.url(), req.failure()?.errorText));
    page.on('response', res => {
      if (res.status() >= 400) console.log('RESP ERROR:', res.url(), res.status());
    });

    await authenticateAndGoToTopology(page);

    // 1. Verify Page Header & Semantics
    await expect(page.locator('.topo-title')).toContainText('Logical Deception Infrastructure');
    await expect(page.locator('.topo-subtitle')).toContainText('Distributed Decoy Nodes Orchestrated by PhantomNet Core Control Plane');
    await expect(page.locator('.topo-badge')).toContainText('LOGICAL TOPOLOGY');

    // 2. Verify Telemetry Sync Badge & Live Feed
    const syncPill = page.locator('.sync-pill');
    await expect(syncPill).toBeVisible();
    await expect(syncPill).toContainText('Synced');

    const liveLabel = page.locator('.live-label');
    await expect(liveLabel).toContainText('LIVE FEED ACTIVE');

    // 3. Verify Controller Node (PHANTOM_OS - CORE CONTROLLER - ONLINE)
    const controller = page.locator('.node-controller');
    await expect(controller).toBeVisible();
    await expect(controller).toContainText('PHANTOM_OS');
    await expect(controller).toContainText('CORE CONTROLLER');
    await expect(controller).toContainText('ONLINE');

    // 4. Verify Honeypot Port Semantics (Host Port → Container Port)
    const honeypotNodes = page.locator('.node-honeypot');
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

    // 5. Verify Details Panel on Node Click
    await sshNode.click();
    const detailsPanel = page.locator('.node-details-panel');
    await expect(detailsPanel).toBeVisible();
    await expect(detailsPanel).toContainText('HOST PORT (EXTERNAL)');
    await expect(detailsPanel).toContainText('2722');
    await expect(detailsPanel).toContainText('CONTAINER PORT (INTERNAL)');
    await expect(detailsPanel).toContainText('2222');
    await expect(detailsPanel).toContainText('Logical Deception Endpoint');

    // 6. Close details panel
    await page.locator('.close-btn').click();
    await expect(detailsPanel).not.toBeVisible();
  });

  for (const vp of VIEWPORTS) {
    test(`RESPONSIVE: Viewport ${vp.name} (${vp.width}x${vp.height}) usability and layout`, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height });

      await authenticateAndGoToTopology(page);

      // Check no horizontal page overflow
      const hasHorizontalOverflow = await page.evaluate(() => {
        return document.documentElement.scrollWidth > window.innerWidth;
      });
      expect(hasHorizontalOverflow).toBe(false);

      // Open details panel and verify it stays bounded within viewport
      const sshNode = page.locator('.node-honeypot').first();
      await sshNode.click();
      const detailsPanel = page.locator('.node-details-panel');
      await expect(detailsPanel).toBeVisible();

      const panelBox = await detailsPanel.boundingBox();
      expect(panelBox).not.toBeNull();
      if (panelBox) {
        expect(panelBox.x).toBeGreaterThanOrEqual(0);
        expect(panelBox.x + panelBox.width).toBeLessThanOrEqual(vp.width + 25);
      }
    });
  }

});
