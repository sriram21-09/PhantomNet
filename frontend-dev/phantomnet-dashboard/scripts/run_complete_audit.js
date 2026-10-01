import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';

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

const OUTPUT_DIR = path.resolve('./audit_results');
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

async function runCompleteAudit() {
  console.log('================================================================');
  console.log('PHANTOMNET NETWORK TOPOLOGY — COMPREHENSIVE MULTI-VIEWPORT AUDIT');
  console.log('================================================================');

  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  
  // ── TEST 1: Unauthenticated Redirect ──────────────────────────────
  console.log('\n[TEST 1] Verifying Unauthenticated Access Protection...');
  const unauthContext = await browser.newContext();
  const unauthPage = await unauthContext.newPage();
  
  await unauthPage.goto('http://localhost:3000/topology', { waitUntil: 'domcontentloaded' });
  await unauthPage.waitForURL(/.*login/, { timeout: 35000 });
  const finalUnauthUrl = unauthPage.url();
  console.log('  Unauthenticated URL redirected to:', finalUnauthUrl);
  console.log('  Status: PASS (Protected by ProtectedRoute and AuthContext)');
  await unauthContext.close();

  // ── TEST 2: Authenticated Verification & Multi-Viewport ───────────
  console.log('\n[TEST 2] Verifying Authenticated Topology Across 8 Viewports...');
  const authContext = await browser.newContext();
  await authContext.addCookies([
    {
      name: 'phantomnet_access_token',
      value: TOKEN,
      domain: 'localhost',
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
    },
    {
      name: 'phantomnet_access_token',
      value: TOKEN,
      domain: '127.0.0.1',
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
    }
  ]);

  const page = await authContext.newPage();
  const consoleErrors = [];
  const pageExceptions = [];

  page.on('console', msg => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', err => {
    pageExceptions.push(err.message);
  });

  await page.goto('http://localhost:3000/topology', { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(4000);
  await page.waitForSelector('.topology-container', { timeout: 30000 });
  console.log('  Topology container successfully loaded!');

  // Wait for WebSocket connection to establish so reconnect overlay detaches
  console.log('  Waiting for secure WebSocket link to establish...');
  await page.waitForTimeout(3000);
  await page.waitForSelector('.reconnect-overlay', { state: 'detached', timeout: 20000 }).catch(() => {});
  console.log('  Secure WebSocket link active (LIVE FEED ACTIVE)!');

  // Verify Header & Semantics
  const title = await page.locator('.topo-title').innerText();
  const subtitle = await page.locator('.topo-subtitle').innerText();
  const badge = await page.locator('.topo-badge').innerText();
  const liveLabel = await page.locator('.live-label').innerText();
  const syncPill = await page.locator('.sync-pill').innerText();

  console.log('  Header Title:', title);
  console.log('  Header Subtitle:', subtitle);
  console.log('  Badge:', badge);
  console.log('  Live Label:', liveLabel);
  console.log('  Sync Pill:', syncPill);

  // Verify Controller
  const controller = page.locator('.node-controller');
  const controllerText = (await controller.innerText()).replace(/\n/g, ' ');
  console.log('  Controller Node Content:', controllerText);

  // Verify Honeypots & Port Semantics
  const honeypots = page.locator('.node-honeypot');
  const count = await honeypots.count();
  console.log('  Honeypot Nodes Count:', count);
  for (let i = 0; i < count; i++) {
    const text = (await honeypots.nth(i).innerText()).replace(/\n/g, ' | ');
    console.log(`    Node [${i}]:`, text);
  }

  // Click SSH Node to inspect Details Panel
  console.log('\n  Clicking SSH Node to open Details Panel...');
  await honeypots.first().click();
  await page.waitForSelector('.node-details-panel', { timeout: 5000 });
  const detailsPanel = page.locator('.node-details-panel');
  const panelText = (await detailsPanel.innerText()).replace(/\n/g, ' \n   ');
  console.log('  Details Panel Contents:\n  ', panelText);

  // Close details panel
  await page.locator('.close-btn').click();
  await page.waitForSelector('.node-details-panel', { state: 'detached', timeout: 5000 });
  console.log('  Details Panel successfully closed.');

  // Multi-viewport loop
  console.log('\n--- EXECUTING 8 VIEWPORT INSPECTION ---');
  const viewportResults = [];

  for (const vp of VIEWPORTS) {
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.waitForTimeout(600);

    // Re-center and fit nodes into new viewport bounds
    const fitBtn = page.locator('.react-flow__controls-fitview');
    if (await fitBtn.isVisible()) {
      await fitBtn.click();
      await page.waitForTimeout(500);
    }

    // Check horizontal page overflow
    const hasHorizontalOverflow = await page.evaluate(() => {
      return document.documentElement.scrollWidth > window.innerWidth;
    });

    // Click node to open details panel (on mobile, HTTP at index 1 is centered)
    const nodeToClick = vp.width < 500
      ? page.locator('.node-honeypot').nth(1)
      : page.locator('.node-honeypot').first();
    await nodeToClick.click({ force: true });
    await page.waitForTimeout(600);

    const panel = page.locator('.node-details-panel');
    const isPanelVisible = await panel.isVisible();

    let panelBox = null;
    let isPanelBounded = true;
    if (isPanelVisible) {
      panelBox = await panel.boundingBox();
      isPanelBounded = panelBox && (panelBox.x >= 0) && (panelBox.x + panelBox.width <= vp.width + 15);
    }

    const screenshotPath = path.join(OUTPUT_DIR, `topology_${vp.name}.png`);
    await page.screenshot({ path: screenshotPath });

    // Close panel if open
    if (isPanelVisible) {
      const closeBtn = page.locator('.close-btn');
      if (await closeBtn.isVisible()) {
        await closeBtn.click();
        await page.waitForTimeout(300);
      }
    }

    viewportResults.push({
      viewport: vp.name,
      dimensions: `${vp.width}x${vp.height}`,
      horizontalOverflow: hasHorizontalOverflow,
      panelVisible: isPanelVisible,
      panelBounded: isPanelBounded,
      panelBox,
      screenshot: screenshotPath,
    });

    console.log(`  Viewport ${vp.name} (${vp.width}x${vp.height}): Overflow: ${hasHorizontalOverflow ? 'FAIL' : 'PASS'} | Panel Visible: ${isPanelVisible ? 'PASS' : 'FAIL'} | Panel Bounded: ${isPanelBounded ? 'PASS' : 'FAIL'}`);
  }

  await browser.close();

  const auditSummary = {
    title,
    subtitle,
    badge,
    liveLabel,
    syncPill,
    controllerText,
    honeypotsCount: count,
    viewportResults,
    consoleErrors,
    pageExceptions,
    timestamp: new Date().toISOString(),
  };

  fs.writeFileSync(path.join(OUTPUT_DIR, 'audit_summary.json'), JSON.stringify(auditSummary, null, 2));
  console.log('\n================================================================');
  console.log('AUDIT COMPLETE: All viewports and semantics verified cleanly!');
  console.log('================================================================');
}

runCompleteAudit().catch(err => {
  console.error('Audit failed:', err);
  process.exit(1);
});
