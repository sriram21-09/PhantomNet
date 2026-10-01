import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';

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

const SCREENSHOT_DIR = path.resolve('./audit_screenshots');
if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

async function runAudit() {
  console.log('--- STARTING TOPOLOGY PLAYWRIGHT VERIFICATION ---');
  
  // Launch Chrome or Edge
  const browser = await chromium.launch({
    headless: true,
    channel: 'msedge', // use system Edge or chrome
  });

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
  });

  const page = await context.newPage();
  const consoleErrors = [];
  const pageExceptions = [];

  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });

  page.on('pageerror', err => {
    pageExceptions.push(err.message);
  });

  // 1. Login
  console.log('Navigating to http://127.0.0.1:3000/login ...');
  await page.goto('http://127.0.0.1:3000/login', { waitUntil: 'networkidle' });

  // Fill credentials if on login page
  const usernameInput = await page.$('input[name="username"], input[type="text"]');
  if (usernameInput) {
    console.log('Submitting login credentials...');
    await page.fill('input[name="username"], input[type="text"]', 'admin');
    await page.fill('input[name="password"], input[type="password"]', 'PhantomNet_SecAdmin_2026!');
    await page.click('button[type="submit"]');
    await page.waitForNavigation({ waitUntil: 'networkidle' }).catch(() => {});
  }

  // 2. Navigate to /topology
  console.log('Navigating to http://127.0.0.1:3000/topology ...');
  await page.goto('http://127.0.0.1:3000/topology', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);

  // 3. Inspect Header and Semantics
  const titleText = await page.textContent('.topology-title, h1, .header-title').catch(() => '');
  const subtitleText = await page.textContent('.topology-subtitle, .header-subtitle').catch(() => '');
  console.log('Title text:', titleText?.trim());
  console.log('Subtitle text:', subtitleText?.trim());

  // Check sync badge
  const syncBadge = await page.$('.telemetry-sync-badge');
  const syncBadgeText = syncBadge ? await syncBadge.innerText() : 'NOT_FOUND';
  console.log('Sync badge text:', syncBadgeText.replace(/\n/g, ' '));

  // Check event counter
  const eventCounter = await page.$('.topology-stat-pill');
  const eventCounterText = eventCounter ? await eventCounter.innerText() : 'NOT_FOUND';
  console.log('Event counter pill:', eventCounterText.replace(/\n/g, ' '));

  // 4. Verify Nodes
  const nodes = await page.$$eval('.react-flow__node', els => els.map(e => e.innerText));
  console.log('Nodes found count:', nodes.length);
  nodes.forEach((n, idx) => console.log(`Node ${idx}:`, n.replace(/\n/g, ' | ')));

  // 5. Test Details Panel click on SSH node
  const sshNode = await page.$('.react-flow__node-honeypot');
  if (sshNode) {
    console.log('Clicking honeypot node to open Details Panel...');
    await sshNode.click();
    await page.waitForTimeout(500);
    const detailsPanel = await page.$('.node-details-panel');
    if (detailsPanel) {
      const detailsText = await detailsPanel.innerText();
      console.log('Details Panel content:\n', detailsText);
    }
  }

  // 6. Test all 8 viewports
  console.log('\n--- TESTING 8 VIEWPORTS ---');
  const viewportResults = [];

  for (const vp of VIEWPORTS) {
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.waitForTimeout(500);

    const hasHorizontalOverflow = await page.evaluate(() => {
      return document.documentElement.scrollWidth > window.innerWidth;
    });

    const isPanelVisible = await page.evaluate(() => {
      const panel = document.querySelector('.node-details-panel');
      if (!panel) return false;
      const rect = panel.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0 && rect.bottom <= window.innerHeight + 50;
    });

    const screenshotPath = path.join(SCREENSHOT_DIR, `topology_${vp.name}.png`);
    await page.screenshot({ path: screenshotPath });

    viewportResults.push({
      viewport: vp.name,
      width: vp.width,
      height: vp.height,
      horizontalOverflow: hasHorizontalOverflow,
      detailsPanelUsable: isPanelVisible,
      screenshot: screenshotPath,
    });

    console.log(`Viewport ${vp.name}: Overflow-X: ${hasHorizontalOverflow ? 'FAIL' : 'PASS'}, Details Panel Usable: ${isPanelVisible ? 'PASS' : 'N/A'}`);
  }

  console.log('\n--- CONSOLE ERRORS ---');
  console.log('Console Errors count:', consoleErrors.length);
  consoleErrors.forEach(e => console.log('  Error:', e));

  console.log('\n--- PAGE EXCEPTIONS ---');
  console.log('Page Exceptions count:', pageExceptions.length);
  pageExceptions.forEach(e => console.log('  Exception:', e));

  await browser.close();

  const finalSummary = {
    titleText,
    subtitleText,
    syncBadgeText,
    eventCounterText,
    nodesCount: nodes.length,
    viewportResults,
    consoleErrors,
    pageExceptions,
  };

  fs.writeFileSync('./audit_screenshots/summary.json', JSON.stringify(finalSummary, null, 2));
  console.log('\n--- AUDIT COMPLETE: summary.json saved ---');
}

runAudit().catch(err => {
  console.error('Audit failed with error:', err);
  process.exit(1);
});
