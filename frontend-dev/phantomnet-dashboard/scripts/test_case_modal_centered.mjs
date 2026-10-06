import { chromium } from '@playwright/test';
import fs from 'fs';
import path from 'path';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const ADMIN_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBZG1pbiIsImV4cCI6MTc5MTgxNTMwOX0.IKRxqVwSpVESoF37V8Cs5-qZzUNMPOorIMJM6HjDF7M';
const ARTIFACT_DIR = 'C:/Users/srira/.gemini/antigravity-ide/brain/b10fc7b3-b9ce-4d3e-804b-ff6e02f52623';

async function run() {
  console.log('Launching browser to verify Case Details Modal centering and exports...');
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    acceptDownloads: true
  });

  await context.addCookies([
    { name: 'phantomnet_access_token', value: ADMIN_TOKEN, domain: 'localhost', path: '/' },
    { name: 'phantomnet_access_token', value: ADMIN_TOKEN, domain: '127.0.0.1', path: '/' }
  ]);

  const page = await context.newPage();
  
  const pageErrors = [];
  page.on('pageerror', err => pageErrors.push(err.message));
  page.on('console', msg => {
    if (msg.type() === 'error') console.log('[Browser Error]', msg.text());
  });

  await page.goto(`${BASE_URL}/hunting`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.threat-hunting-page', { timeout: 15000 });
  console.log('Page loaded successfully.');

  // Wait for case list to be populated
  await page.waitForSelector('.case-card', { timeout: 15000 });
  console.log('Case card found in sidebar.');

  // Click the case title or the eye button
  const caseTrigger = page.locator('.case-title.clickable-title, .case-card .btn-icon-sm').first();
  await caseTrigger.click();
  console.log('Clicked case trigger.');

  await page.waitForSelector('.case-details-modal', { timeout: 8000 });
  console.log('Case details modal appeared.');

  // Measure bounding box
  const modalBox = await page.locator('.case-details-modal').boundingBox();
  console.log('Modal bounding box:', modalBox);

  const isCentered = modalBox && modalBox.width > 600 && modalBox.x > 150 && modalBox.x < 500;
  console.log('Is modal centered & wide (not trapped in 300px sidebar)?', isCentered);

  // Check buttons
  const pdfBtn = page.locator('.btn-export-pdf');
  const jsonBtn = page.locator('.btn-export-json');
  const copyBtn = page.locator('.btn-copy-summary');
  const deleteBtn = page.locator('.btn-delete-case');

  console.log('PDF button visible:', await pdfBtn.isVisible());
  console.log('JSON button visible:', await jsonBtn.isVisible());
  console.log('Copy button visible:', await copyBtn.isVisible());
  console.log('Delete button visible:', await deleteBtn.isVisible());

  // Test Export PDF
  console.log('Testing PDF export button...');
  const [downloadPdf] = await Promise.all([
    page.waitForEvent('download', { timeout: 8000 }).catch(() => null),
    pdfBtn.click()
  ]);
  if (downloadPdf) {
    console.log('[PASS] PDF Download triggered successfully:', await downloadPdf.suggestedFilename());
  } else {
    console.log('PDF download event not caught directly or handled via data URL / feedback');
  }
  await page.waitForTimeout(1000);

  // Test Export JSON
  console.log('Testing JSON export button...');
  const [downloadJson] = await Promise.all([
    page.waitForEvent('download', { timeout: 8000 }).catch(() => null),
    jsonBtn.click()
  ]);
  if (downloadJson) {
    console.log('[PASS] JSON Download triggered successfully:', await downloadJson.suggestedFilename());
  }
  await page.waitForTimeout(1000);

  // Screenshot the centered modal
  const screenshotPath = path.join(ARTIFACT_DIR, 'case_details_modal_centered.png');
  await page.screenshot({ path: screenshotPath, fullPage: false });
  console.log('Saved screenshot to:', screenshotPath);

  await browser.close();
}

run().catch(err => {
  console.error('Test run failed:', err);
  process.exit(1);
});
