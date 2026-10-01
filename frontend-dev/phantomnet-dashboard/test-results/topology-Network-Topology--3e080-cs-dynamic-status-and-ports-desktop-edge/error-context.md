# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: topology.spec.js >> Network Topology Remediation & Verification Suite >> NT-01: Authenticated topology rendering, semantics, dynamic status, and ports
- Location: tests\e2e\topology.spec.js:33:3

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: page.waitForSelector: Test timeout of 30000ms exceeded.
Call log:
  - waiting for locator('.topology-container') to be visible

```

# Page snapshot

```yaml
- generic [ref=e3]:
  - navigation [ref=e4]:
    - generic [ref=e5]:
      - link "PhantomNet" [ref=e6] [cursor=pointer]:
        - /url: /
      - generic "Switch to light mode" [ref=e12] [cursor=pointer]: Light Mode
  - generic [ref=e18]: AUTHENTICATING PHANTOMNET SECURE SESSION...
```

# Test source

```ts
  1   | import { test, expect } from '@playwright/test';
  2   | 
  3   | const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBZG1pbiIsImV4cCI6MTc5MTM4MTgwNn0.sMfONtOn0vn81EMl27A8kQWYhaNZvpMu2kbahWurPoU';
  4   | 
  5   | const VIEWPORTS = [
  6   |   { name: '1920x1080', width: 1920, height: 1080 },
  7   |   { name: '1440x900',  width: 1440, height: 900 },
  8   |   { name: '1366x768',  width: 1366, height: 768 },
  9   |   { name: '1024x768',  width: 1024, height: 768 },
  10  |   { name: '768x1024',  width: 768,  height: 1024 },
  11  |   { name: '480x900',   width: 480,  height: 900 },
  12  |   { name: '390x844',   width: 390,  height: 844 },
  13  |   { name: '360x800',   width: 360,  height: 800 },
  14  | ];
  15  | 
  16  | async function authenticateAndGoToTopology(page) {
  17  |   await page.context().addCookies([
  18  |     { name: 'phantomnet_access_token', value: TOKEN, url: 'http://127.0.0.1:3000' },
  19  |     { name: 'phantomnet_access_token', value: TOKEN, url: 'http://localhost:3000' },
  20  |   ]);
  21  |   await page.goto('http://127.0.0.1:3000/topology');
> 22  |   await page.waitForSelector('.topology-container', { timeout: 30000 });
      |              ^ Error: page.waitForSelector: Test timeout of 30000ms exceeded.
  23  | }
  24  | 
  25  | test.describe('Network Topology Remediation & Verification Suite', () => {
  26  | 
  27  |   test('SEC-01: Unauthenticated request redirects to /login', async ({ page }) => {
  28  |     await page.context().clearCookies();
  29  |     await page.goto('http://127.0.0.1:3000/topology');
  30  |     await expect(page).toHaveURL(/.*login/, { timeout: 15000 });
  31  |   });
  32  | 
  33  |   test('NT-01: Authenticated topology rendering, semantics, dynamic status, and ports', async ({ page }) => {
  34  |     page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()));
  35  |     page.on('requestfailed', req => console.log('REQ FAILED:', req.url(), req.failure()?.errorText));
  36  |     page.on('response', res => {
  37  |       if (res.status() >= 400) console.log('RESP ERROR:', res.url(), res.status());
  38  |     });
  39  | 
  40  |     await authenticateAndGoToTopology(page);
  41  | 
  42  |     // 1. Verify Page Header & Semantics
  43  |     await expect(page.locator('.topo-title')).toContainText('Logical Deception Infrastructure');
  44  |     await expect(page.locator('.topo-subtitle')).toContainText('Distributed Decoy Nodes Orchestrated by PhantomNet Core Control Plane');
  45  |     await expect(page.locator('.topo-badge')).toContainText('LOGICAL TOPOLOGY');
  46  | 
  47  |     // 2. Verify Telemetry Sync Badge & Live Feed
  48  |     const syncPill = page.locator('.sync-pill');
  49  |     await expect(syncPill).toBeVisible();
  50  |     await expect(syncPill).toContainText('Synced');
  51  | 
  52  |     const liveLabel = page.locator('.live-label');
  53  |     await expect(liveLabel).toContainText('LIVE FEED ACTIVE');
  54  | 
  55  |     // 3. Verify Controller Node (PHANTOM_OS - CORE CONTROLLER - ONLINE)
  56  |     const controller = page.locator('.node-controller');
  57  |     await expect(controller).toBeVisible();
  58  |     await expect(controller).toContainText('PHANTOM_OS');
  59  |     await expect(controller).toContainText('CORE CONTROLLER');
  60  |     await expect(controller).toContainText('ONLINE');
  61  | 
  62  |     // 4. Verify Honeypot Port Semantics (Host Port → Container Port)
  63  |     const honeypotNodes = page.locator('.node-honeypot');
  64  |     await expect(honeypotNodes).toHaveCount(4);
  65  | 
  66  |     // SSH: 2722 → 2222
  67  |     const sshNode = honeypotNodes.filter({ hasText: 'SSH' });
  68  |     await expect(sshNode).toBeVisible();
  69  |     await expect(sshNode).toContainText('PORT 2722 → 2222');
  70  |     await expect(sshNode).toContainText('ACTIVE');
  71  | 
  72  |     // HTTP: 8080 → 8080
  73  |     const httpNode = honeypotNodes.filter({ hasText: 'HTTP' });
  74  |     await expect(httpNode).toBeVisible();
  75  |     await expect(httpNode).toContainText('PORT 8080 → 8080');
  76  | 
  77  |     // FTP: 2721 → 2121
  78  |     const ftpNode = honeypotNodes.filter({ hasText: 'FTP' });
  79  |     await expect(ftpNode).toBeVisible();
  80  |     await expect(ftpNode).toContainText('PORT 2721 → 2121');
  81  | 
  82  |     // SMTP: 2725 → 2525
  83  |     const smtpNode = honeypotNodes.filter({ hasText: 'SMTP' });
  84  |     await expect(smtpNode).toBeVisible();
  85  |     await expect(smtpNode).toContainText('PORT 2725 → 2525');
  86  | 
  87  |     // 5. Verify Details Panel on Node Click
  88  |     await sshNode.click();
  89  |     const detailsPanel = page.locator('.node-details-panel');
  90  |     await expect(detailsPanel).toBeVisible();
  91  |     await expect(detailsPanel).toContainText('HOST PORT (EXTERNAL)');
  92  |     await expect(detailsPanel).toContainText('2722');
  93  |     await expect(detailsPanel).toContainText('CONTAINER PORT (INTERNAL)');
  94  |     await expect(detailsPanel).toContainText('2222');
  95  |     await expect(detailsPanel).toContainText('Logical Deception Endpoint');
  96  | 
  97  |     // 6. Close details panel
  98  |     await page.locator('.close-btn').click();
  99  |     await expect(detailsPanel).not.toBeVisible();
  100 |   });
  101 | 
  102 |   for (const vp of VIEWPORTS) {
  103 |     test(`RESPONSIVE: Viewport ${vp.name} (${vp.width}x${vp.height}) usability and layout`, async ({ page }) => {
  104 |       await page.setViewportSize({ width: vp.width, height: vp.height });
  105 | 
  106 |       await authenticateAndGoToTopology(page);
  107 | 
  108 |       // Check no horizontal page overflow
  109 |       const hasHorizontalOverflow = await page.evaluate(() => {
  110 |         return document.documentElement.scrollWidth > window.innerWidth;
  111 |       });
  112 |       expect(hasHorizontalOverflow).toBe(false);
  113 | 
  114 |       // Open details panel and verify it stays bounded within viewport
  115 |       const sshNode = page.locator('.node-honeypot').first();
  116 |       await sshNode.click();
  117 |       const detailsPanel = page.locator('.node-details-panel');
  118 |       await expect(detailsPanel).toBeVisible();
  119 | 
  120 |       const panelBox = await detailsPanel.boundingBox();
  121 |       expect(panelBox).not.toBeNull();
  122 |       if (panelBox) {
```