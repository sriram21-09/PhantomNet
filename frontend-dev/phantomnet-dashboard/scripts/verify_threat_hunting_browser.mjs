import { chromium } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const API_URL = process.env.API_URL || 'http://localhost:8000';

const ADMIN_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBZG1pbiIsImV4cCI6MTc5MTgxNTMwOX0.IKRxqVwSpVESoF37V8Cs5-qZzUNMPOorIMJM6HjDF7M';
const ANALYST_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X2FuYWx5c3QiLCJyb2xlIjoiQW5hbHlzdCIsImV4cCI6MTc5MTgxNTMwOX0.LMf-P0WOUlb4vOwJxrB3oVKAdxSNJ7CR6JN_SdLVtI4';
const VIEWER_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X3ZpZXdlciIsInJvbGUiOiJWaWV3ZXIiLCJleHAiOjE3OTE4MTUzMDl9.ofq7srImJR5hnj2ukvaHq-UikdyMakzXk9sfHU1De-w';

let totalChecks = 0;
let passedChecks = 0;

function check(desc, passed, detail = '') {
  totalChecks++;
  if (passed) {
    passedChecks++;
    console.log(`[PASS] ${desc} ${detail ? '(' + detail + ')' : ''}`);
  } else {
    console.error(`[FAIL] ${desc} ${detail ? '(' + detail + ')' : ''}`);
  }
}

async function runBrowserVerification() {
  console.log('============================================================');
  console.log('STARTING SECTION 24 BROWSER-LEVEL RUNTIME VERIFICATION');
  console.log('============================================================\n');

  const browser = await chromium.launch({ channel: 'msedge', headless: true });

  try {
    // -------------------------------------------------------------
    // PART 1: LOGIN AS ADMIN VIA FORM & HUNT
    // -------------------------------------------------------------
    console.log('--- Step 1-7: Admin Login, Hunt, and Exports ---');
    const adminContext = await browser.newContext({ acceptDownloads: true });
    const page = await adminContext.newPage();

    const pageErrors = [];
    page.on('pageerror', err => pageErrors.push(err.message));
    page.on('console', msg => {
      if (msg.type() === 'error' && !msg.text().includes('401 (Unauthorized)')) {
        pageErrors.push(msg.text());
      }
    });

    // 1. Navigate to login
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[type="text"], input[name="username"], input[placeholder*="username" i]', { timeout: 10000 });
    
    // Fill credentials
    const userInput = page.locator('input[type="text"], input[name="username"], input[placeholder*="username" i]').first();
    const passInput = page.locator('input[type="password"]').first();
    await userInput.fill('admin');
    await passInput.fill('PhantomNet_SecAdmin_2026!');
    
    const submitBtn = page.locator('button[type="submit"]').first();
    await submitBtn.click();
    await page.waitForURL('**/dashboard', { timeout: 10000 }).catch(() => null);
    await page.waitForTimeout(1000);

    check('Admin login succeeds', !page.url().includes('/login') || page.url().includes('/dashboard'), page.url());

    // 2. Navigate to /hunting
    await page.goto(`${BASE_URL}/hunting`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('.threat-hunting-page', { timeout: 10000 });
    
    const pageTitle = await page.textContent('.hunting-header h1');
    check('Threat Hunting page title rendered', pageTitle?.includes('Professional Threat Hunting'), pageTitle?.trim());

    const badge = await page.textContent('.status-badge.session');
    check('Hunting Session badge rendered truthfully', badge?.includes('HUNTING SESSION'), badge?.trim());

    // 3. Execute hunt: threat_level equals LOW
    // Use QueryBuilder field select
    const fieldSelect = page.locator('.field-select').first();
    await fieldSelect.selectOption('threat_level');
    await page.waitForTimeout(300);

    const opSelect = page.locator('.op-select').first();
    await opSelect.selectOption('equals');
    await page.waitForTimeout(300);

    const valSelect = page.locator('.val-select').first();
    await valSelect.selectOption('LOW');
    await page.waitForTimeout(300);

    // Click execute query button
    const searchBtn = page.locator('.btn-execute').first();
    await searchBtn.click();
    await page.waitForSelector('.event-card', { timeout: 10000 }).catch(() => null);
    await page.waitForTimeout(1000);

    // 4. Confirm HTTP 200, results render, no 403 banner
    const errorBanner = await page.$('.search-error-banner');
    check('No search error banner on valid Admin hunt', errorBanner === null);

    const timelineCards = await page.$$('.event-card');
    check('Timeline rendered events matching LOW', timelineCards.length > 0, `${timelineCards.length} events displayed`);

    // 5. Test CSV export
    const csvBtn = page.locator('.btn-export:has-text("CSV")').first();
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download', { timeout: 5000 }).catch(() => null),
      csvBtn.click()
    ]);
    await page.waitForTimeout(500);
    const exportStatusCSV = await page.textContent('.export-status');
    check('CSV export button triggers export without runtime crash', exportStatusCSV?.includes('CSV Exported!'), exportStatusCSV);

    // 6. Test JSON export
    const jsonBtn = page.locator('.btn-export:has-text("JSON")').first();
    const [jsonDownload] = await Promise.all([
      page.waitForEvent('download', { timeout: 5000 }).catch(() => null),
      jsonBtn.click()
    ]);
    await page.waitForTimeout(500);
    const exportStatusJSON = await page.textContent('.export-status');
    check('JSON export button triggers export cleanly', exportStatusJSON?.includes('JSON Exported!'), exportStatusJSON);

    // 7. Test PDF export
    const pdfBtn = page.locator('.btn-export.pdf').first();
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download', { timeout: 5000 }).catch(() => null),
      pdfBtn.click()
    ]);
    await page.waitForTimeout(1000);
    const exportStatusPDF = await page.textContent('.export-status');
    check('PDF export generates cleanly without autoTable or TypeError', exportStatusPDF?.includes('PDF Exported!'), exportStatusPDF);

    check('Zero uncaught exceptions during Admin hunting workflow', pageErrors.length === 0, pageErrors.join('; '));

    await adminContext.close();

    // -------------------------------------------------------------
    // PART 2: ANALYST ROLE HUNTING ACCESS
    // -------------------------------------------------------------
    console.log('\n--- Step 8-10: Analyst Role Access & Execution ---');
    const analystContext = await browser.newContext();
    await analystContext.addCookies([
      { name: 'phantomnet_access_token', value: ANALYST_TOKEN, domain: 'localhost', path: '/' },
      { name: 'phantomnet_access_token', value: ANALYST_TOKEN, domain: '127.0.0.1', path: '/' }
    ]);
    const analystPage = await analystContext.newPage();
    await analystPage.goto(`${BASE_URL}/hunting`, { waitUntil: 'domcontentloaded' });
    await analystPage.waitForSelector('.threat-hunting-page', { timeout: 10000 });

    const analystHeader = await analystPage.textContent('.hunting-header h1');
    check('Analyst user successfully enters /hunting', analystHeader?.includes('Professional Threat Hunting'));

    // Execute hunt as Analyst
    const analystSearchBtn = analystPage.locator('.btn-execute').first();
    await analystSearchBtn.click();
    await analystPage.waitForTimeout(2000);

    const analystError = await analystPage.$('.search-error-banner');
    check('Analyst hunt executes without 403 RBAC denial', analystError === null);

    await analystContext.close();

    // -------------------------------------------------------------
    // PART 3: VIEWER ROLE ACCESS DENIAL (DEF-FOR-03)
    // -------------------------------------------------------------
    console.log('\n--- Step 11-16: Viewer Role Route Guard & Denial ---');
    const viewerContext = await browser.newContext();
    await viewerContext.addCookies([
      { name: 'phantomnet_access_token', value: VIEWER_TOKEN, domain: 'localhost', path: '/' },
      { name: 'phantomnet_access_token', value: VIEWER_TOKEN, domain: '127.0.0.1', path: '/' }
    ]);
    const viewerPage = await viewerContext.newPage();
    await viewerPage.goto(`${BASE_URL}/hunting`, { waitUntil: 'domcontentloaded' });
    await viewerPage.waitForSelector('.access-denied-container', { timeout: 10000 });

    const deniedHeading = await viewerPage.textContent('.access-denied-container h2');
    check('Viewer is blocked from /hunting with Access Denied', deniedHeading?.includes('Access Denied'), deniedHeading?.trim());

    const deniedText = await viewerPage.textContent('.access-denied-container p');
    check('Access Denied message identifies role Viewer and required roles Admin or Analyst', 
      deniedText?.includes('Viewer') && deniedText?.includes('Admin or Analyst'), 
      deniedText?.trim()
    );

    const returnBtn = await viewerPage.$('.access-denied-container a[href*="dashboard"]');
    check('Return to Dashboard action provided on Access Denied screen', returnBtn !== null);

    // Direct API check from viewer session: API still returns 403
    const viewerApiResp = await viewerPage.evaluate(async () => {
      const res = await fetch('/api/v1/hunting/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify({ logic: 'AND', conditions: [] })
      });
      return { status: res.status, data: await res.json() };
    });
    check('Viewer direct API search strictly rejected with HTTP 403 RBAC', viewerApiResp.status === 403, JSON.stringify(viewerApiResp.data));
    check('Viewer API 403 identifies role requirement', viewerApiResp.data?.detail?.includes('Requires role: Admin, Analyst'));

    await viewerContext.close();

    // -------------------------------------------------------------
    // PART 4: UNAUTHENTICATED REDIRECT
    // -------------------------------------------------------------
    console.log('\n--- Step 17: Unauthenticated Access Redirect ---');
    const unauthContext = await browser.newContext();
    const unauthPage = await unauthContext.newPage();
    await unauthPage.goto(`${BASE_URL}/hunting`, { waitUntil: 'domcontentloaded' });
    await unauthPage.waitForTimeout(1000);

    check('Unauthenticated access to /hunting redirects to /login', unauthPage.url().includes('/login'), unauthPage.url());
    await unauthContext.close();

    // -------------------------------------------------------------
    // PART 5: CSRF ENFORCEMENT & BROWSER INTEGRATION (CSRF-01)
    // -------------------------------------------------------------
    console.log('\n--- Step 18: CSRF Enforcement & Compliance Matrix ---');
    const csrfContext = await browser.newContext();
    await csrfContext.addCookies([
      { name: 'phantomnet_access_token', value: ADMIN_TOKEN, domain: 'localhost', path: '/' },
      { name: 'phantomnet_access_token', value: ADMIN_TOKEN, domain: '127.0.0.1', path: '/' }
    ]);
    const csrfPage = await csrfContext.newPage();
    await csrfPage.goto(`${BASE_URL}/hunting`, { waitUntil: 'domcontentloaded' });

    // Request WITHOUT CSRF header
    const noCsrfResp = await csrfPage.evaluate(async () => {
      // standard fetch without custom header
      const res = await window.fetch('/api/v1/hunting/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logic: 'AND', conditions: [] })
      });
      return { status: res.status, data: await res.json() };
    });

    // Check raw fetch without interceptor (via XMLHttpRequest directly without custom header)
    const rawNoCsrfResp = await csrfPage.evaluate(async () => {
      return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/v1/hunting/search');
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.withCredentials = true;
        xhr.onload = () => resolve({ status: xhr.status, data: JSON.parse(xhr.responseText || '{}') });
        xhr.onerror = () => resolve({ status: xhr.status, data: {} });
        xhr.send(JSON.stringify({ logic: 'AND', conditions: [] }));
      });
    });
    check('Admin request WITHOUT CSRF header is rejected with 403 CSRF', rawNoCsrfResp.status === 403, JSON.stringify(rawNoCsrfResp.data));
    check('403 detail explicitly indicates CSRF failure', rawNoCsrfResp.data?.detail?.includes('CSRF validation failed'));

    // Request WITH CSRF header (via frontend Axios / enhanced fetch)
    const withCsrfResp = await csrfPage.evaluate(async () => {
      return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/v1/hunting/search');
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        xhr.withCredentials = true;
        xhr.onload = () => resolve({ status: xhr.status, data: JSON.parse(xhr.responseText || '{}') });
        xhr.onerror = () => resolve({ status: xhr.status, data: {} });
        xhr.send(JSON.stringify({ logic: 'AND', conditions: [] }));
      });
    });
    check('Admin request WITH required X-Requested-With header succeeds with HTTP 200', withCsrfResp.status === 200, `Total: ${withCsrfResp.data?.total}`);

    await csrfContext.close();

  } finally {
    await browser.close();
  }

  console.log('\n============================================================');
  console.log(`FINAL BROWSER VERIFICATION: ${passedChecks}/${totalChecks} CHECKS PASSED`);
  console.log('============================================================\n');

  if (passedChecks < totalChecks) {
    process.exit(1);
  }
}

runBrowserVerification().catch(err => {
  console.error('Browser verification failed with unhandled exception:', err);
  process.exit(1);
});
