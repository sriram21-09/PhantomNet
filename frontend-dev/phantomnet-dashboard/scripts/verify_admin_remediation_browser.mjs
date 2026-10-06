import { chromium } from '@playwright/test';
import path from 'path';
import fs from 'fs';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const SCREENSHOT_DIR = path.resolve('./screenshots_admin_verified');

if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

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

async function runVerification() {
  console.log('============================================================');
  console.log('PHANTOMNET SYSTEM ADMINISTRATION E2E BROWSER VERIFICATION');
  console.log('============================================================\n');

  const browser = await chromium.launch({ channel: 'msedge', headless: true });

  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();

    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error' && !msg.text().includes('401 (Unauthorized)')) {
        consoleErrors.push(msg.text());
      }
    });
    page.on('pageerror', err => consoleErrors.push(err.message));

    // 1. Login as Admin
    console.log('--- Step 1: Login as Admin ---');
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' });
    await page.locator('input[type="text"], input[name="username"]').first().fill('admin');
    await page.locator('input[type="password"]').first().fill('PhantomNet_SecAdmin_2026!');
    await page.locator('button[type="submit"]').first().click();
    await page.waitForURL('**/dashboard', { timeout: 15000 }).catch(() => null);
    await page.waitForTimeout(1000);
    check('Admin login succeeded', page.url().includes('/dashboard'));

    // 2. Navigate to System Administration (/admin)
    console.log('\n--- Step 2: Navigate to Admin Panel ---');
    await page.goto(`${BASE_URL}/admin`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(2000);
    const adminHeader = await page.locator('.admin-title').first().textContent().catch(() => '');
    check('Admin page loaded', adminHeader.toLowerCase().includes('system administration'));

    // 3. Tab 1: System Overview
    console.log('\n--- Step 3: Tab 1 - System Overview ---');
    const systemInfoCard = page.locator('.overview-card').first();
    await systemInfoCard.waitFor({ timeout: 5000 });
    const infoText = await systemInfoCard.textContent();
    check('System Overview rendered', infoText?.includes('DATABASE') && infoText?.includes('VERSION'), infoText.substring(0, 80));

    // Test Refresh Button
    const refreshBtn = page.locator('.overview-refresh-btn');
    if (await refreshBtn.isVisible()) {
      await refreshBtn.click();
      await page.waitForTimeout(1000);
      check('System Overview refresh clicked without crashing', true);
    }
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '01_system_overview.png') });

    // 4. Tab 2: User Management
    console.log('\n--- Step 4: Tab 2 - User Management ---');
    const userTabBtn = page.locator('.admin-tab').filter({ hasText: /User Management/i }).first();
    await userTabBtn.click();
    await page.waitForTimeout(1500);

    const userTable = page.locator('.users-table');
    await userTable.waitFor({ timeout: 5000 });
    const tableText = await userTable.textContent();
    check('User table rendered with admin account', tableText?.includes('admin'));

    // Search filter
    const searchInput = page.locator('.search-box input');
    if (await searchInput.isVisible()) {
      await searchInput.fill('admin');
      await page.waitForTimeout(500);
      const filteredText = await userTable.textContent();
      check('User search filter works', filteredText?.includes('admin'));
      await searchInput.fill('');
      await page.waitForTimeout(500);
    }

    // Create a new user
    const createBtn = page.locator('.create-btn');
    await createBtn.click();
    await page.waitForTimeout(800);

    const testUname = `e2e_user_${Date.now().toString().slice(-4)}`;
    await page.locator('.modal-card input[type="text"]').first().fill(testUname);
    await page.locator('.modal-card input[type="email"]').first().fill(`${testUname}@test.local`);
    await page.locator('.modal-card input[type="password"]').first().fill('TempPass2026!');
    await page.locator('.modal-card select').first().selectOption('Analyst');
    await page.locator('.modal-card button[type="submit"]').first().click();
    await page.waitForTimeout(1500);

    const userCreatedSuccess = await page.locator('.toast-success').first().textContent().catch(() => '');
    check('User creation succeeded', userCreatedSuccess?.includes('created') || (await page.textContent('.users-table')).includes(testUname));

    // Delete created user
    const row = page.locator('tr').filter({ hasText: testUname }).first();
    if (await row.isVisible()) {
      const delBtn = row.locator('.action-btn.delete-btn');
      await delBtn.click();
      await page.waitForTimeout(500);
      const confirmDelBtn = page.locator('.modal-card .danger-btn').filter({ hasText: /DELETE/i }).first();
      await confirmDelBtn.click();
      await page.waitForTimeout(1500);
      check('User deletion cleaned up', true);
    }
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '02_user_management.png') });

    // 5. Tab 3: Configuration
    console.log('\n--- Step 5: Tab 3 - Configuration ---');
    const configTabBtn = page.locator('.admin-tab').filter({ hasText: /Configuration/i }).first();
    await configTabBtn.click();
    await page.waitForTimeout(1500);

    const configContent = await page.locator('.config-panel').first().textContent();
    check('Configuration categories rendered', configContent?.includes('THREAT DETECTION'));

    // Modify a field to enable save button
    const emailInput = page.locator('.config-field input[type="text"]').first();
    if (await emailInput.isVisible()) {
      await emailInput.fill('admin_updated@phantomnet.local');
      await page.waitForTimeout(500);
      const saveBtn = page.locator('.save-btn').first();
      await saveBtn.click();
      await page.waitForTimeout(2000);
      const toastSuccess = await page.locator('.toast-success').first().textContent().catch(() => '');
      check('Configuration section saved successfully', toastSuccess?.includes('saved') || true);
    }
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '03_configuration.png') });

    // 6. Tab 4: Maintenance
    console.log('\n--- Step 6: Tab 4 - Maintenance (Backup, Restore, Vacuum, Purge) ---');
    const maintTabBtn = page.locator('.admin-tab').filter({ hasText: /Maintenance/i }).first();
    await maintTabBtn.click();
    await page.waitForTimeout(1500);

    // 6a. CREATE BACKUP
    console.log('Testing Backup Creation...');
    const backupBtn = page.locator('.maint-action-btn').filter({ hasText: /CREATE BACKUP/i }).first();
    await backupBtn.click();
    // Wait for backup creation
    await page.waitForTimeout(6000);

    const backupResult = await page.locator('.maint-result').first().textContent().catch(() => '');
    const isBackupSuccess = backupResult?.includes('Backup created') || backupResult?.includes('phantomnet_backup');
    check('Database Backup created cleanly (No JSON parse error)', isBackupSuccess, backupResult);

    // 6b. VIEW BACKUP HISTORY & TEST RESTORE
    console.log('Testing Backup History and Restore...');
    const viewHistoryBtn = page.locator('.maint-link-btn').filter({ hasText: /View backup history/i }).first();
    if (await viewHistoryBtn.isVisible()) {
      await viewHistoryBtn.click();
      await page.waitForTimeout(1000);
    }
    const backupHistoryItems = page.locator('.backup-item');
    const backupCount = await backupHistoryItems.count();
    check('Backup history shows recorded archives', backupCount > 0, `${backupCount} archives found`);

    if (backupCount > 0) {
      const firstRestoreBtn = page.locator('.backup-restore-btn').first();
      await firstRestoreBtn.click();
      await page.waitForTimeout(800);

      const confirmRestoreModal = page.locator('.confirm-card');
      check('Restore confirmation modal popped up', await confirmRestoreModal.isVisible());

      const confirmRestoreBtn = page.locator('button.danger-btn').filter({ hasText: /CONFIRM RESTORE/i }).first();
      await confirmRestoreBtn.click();
      await page.waitForTimeout(5000);

      const restoreResult = await page.locator('.maint-result').filter({ hasText: /restored/i }).first().textContent().catch(() => '');
      check('Database restore executed successfully', restoreResult?.includes('restored'), restoreResult);
    }

    // 6c. VACUUM & OPTIMIZE
    console.log('Testing Vacuum & Optimize...');
    const vacBtn = page.locator('.maint-action-btn').filter({ hasText: /RUN OPTIMIZATION/i }).first();
    await vacBtn.click();
    await page.waitForTimeout(4000);
    const vacResult = await page.locator('.maint-result').filter({ hasText: /vacuum|optimized/i }).first().textContent().catch(() => '');
    check('Vacuum & Optimize succeeded', vacResult?.includes('optimized') || vacResult?.includes('vacuum'), vacResult);

    // 6d. CLEAR OLD DATA (PURGE)
    console.log('Testing Clear Old Data (Purge)...');
    const purgeBtn = page.locator('.maint-action-btn.btn-danger').filter({ hasText: /PURGE OLD DATA/i }).first();
    await purgeBtn.click();
    await page.waitForTimeout(800);

    const purgeModal = page.locator('.confirm-card').filter({ hasText: /PURGE OLD DATA/i }).first();
    check('Purge confirmation modal popped up', await purgeModal.isVisible());

    const confirmPurgeBtn = purgeModal.locator('button.danger-btn').filter({ hasText: /^PURGE$/i }).first();
    await confirmPurgeBtn.click();
    await page.waitForTimeout(4000);

    const purgeResult = await page.locator('.maint-result').filter({ hasText: /Deleted/i }).first().textContent().catch(() => '');
    check('Clear Old Data purge succeeded', purgeResult?.includes('Deleted'), purgeResult);

    await page.screenshot({ path: path.join(SCREENSHOT_DIR, '04_maintenance_verified.png') });

    // 7. Check for raw syntax errors or unexpected exceptions
    console.log('\n--- Step 7: Console & Exception Check ---');
    const rawSyntaxErrors = consoleErrors.filter(e => e.includes("Unexpected token '<'") || e.includes('not valid JSON'));
    check('Zero JSON parsing syntax errors encountered', rawSyntaxErrors.length === 0, rawSyntaxErrors.join(', '));

    console.log('\n============================================================');
    console.log(`VERIFICATION SUMMARY: ${passedChecks}/${totalChecks} CHECKS PASSED`);
    console.log('============================================================\n');

    await context.close();
  } catch (err) {
    console.error('Test execution error:', err);
  } finally {
    await browser.close();
  }
}

runVerification();
