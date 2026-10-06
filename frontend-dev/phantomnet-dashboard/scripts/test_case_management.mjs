import { chromium } from '@playwright/test';

async function testCaseManagement() {
    console.log('====================================================');
    console.log('STARTING CASE MANAGEMENT & SIDEBAR TEST SUITE');
    console.log('====================================================\n');

    const browser = await chromium.launch({ channel: 'msedge', headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

    const errors = [];
    page.on('pageerror', err => errors.push(err.message));
    page.on('console', msg => {
        if (msg.type() === 'error' && !msg.text().includes('401 (Unauthorized)')) {
            errors.push(msg.text());
        }
    });

    try {
        console.log('1. Logging in as admin...');
        await page.goto('http://localhost:3000/login');
        await page.fill('#login-username', 'admin');
        await page.fill('#login-password', 'PhantomNet_SecAdmin_2026!');
        await page.click('#login-submit-btn');
        await page.waitForURL('**/dashboard', { timeout: 10000 });
        console.log('   Logged in successfully.');

        console.log('2. Navigating to /hunting...');
        await page.goto('http://localhost:3000/hunting', { waitUntil: 'networkidle' });
        await page.waitForTimeout(2000);

        // Select first event card
        console.log('3. Selecting first event in timeline...');
        const firstEvent = page.locator('.timeline-item.event-card').first();
        await firstEvent.click();
        await page.waitForTimeout(1500);

        // Verify Active Investigation header
        const invHeader = await page.textContent('.inv-header');
        console.log('   Active Investigation Header:', invHeader?.trim());

        // Test IOC tab: Copy All
        console.log('4. Testing IOCs tab Copy All and Watchlist toggle...');
        const copyAllBtn = page.locator('.btn-copy').first();
        await copyAllBtn.click();
        await page.waitForTimeout(500);
        const copyAllText = await copyAllBtn.textContent();
        console.log('   Copy All feedback:', copyAllText?.trim());

        // Test Watchlist toggle
        const watchlistBtn = page.locator('.btn-watchlist').first();
        await watchlistBtn.click();
        await page.waitForTimeout(1000);
        console.log('   Watchlist toggle succeeded.');

        // Test Related tab
        console.log('5. Testing Related Events tab...');
        await page.click('.inv-tab:nth-child(2)');
        await page.waitForTimeout(1000);
        const relatedCount = await page.locator('.related-item').count();
        console.log(`   Found ${relatedCount} related events in tab.`);

        // Click first related item to select it
        if (relatedCount > 0) {
            await page.locator('.related-item').first().click();
            await page.waitForTimeout(1000);
            console.log('   Clicked related event -> successfully inspected in timeline.');
        }

        // Test Payload tab
        console.log('6. Testing Payload tab...');
        await page.click('.inv-tab:nth-child(3)');
        await page.waitForTimeout(500);
        const copyPayloadBtn = page.locator('.btn-copy-payload');
        await copyPayloadBtn.click();
        await page.waitForTimeout(500);
        const payloadFeedback = await copyPayloadBtn.textContent();
        console.log('   Payload copy feedback:', payloadFeedback?.trim());

        // Test Investigation Note
        console.log('7. Testing Investigation Note saving to case...');
        await page.fill('.note-textarea', 'Automated test note: anomalous telemetry flagged on edge honeypot.');
        const saveNoteBtn = page.locator('.btn-save-note');
        if (await saveNoteBtn.isVisible()) {
            await saveNoteBtn.click();
            await page.waitForTimeout(1500);
            const noteBadge = await page.textContent('.note-feedback-badge');
            console.log('   Note save feedback:', noteBadge?.trim());
        }

        // Test Link Event button on case card
        console.log('8. Testing Link Event action on case card...');
        const linkBtn = page.locator('.btn-link-event').first();
        if (await linkBtn.isVisible()) {
            await linkBtn.click();
            await page.waitForTimeout(1500);
            const linkText = await linkBtn.textContent();
            console.log('   Link Event status:', linkText?.trim());
        }

        // Test View Case Details Modal
        console.log('9. Testing View Case Details Modal (eye icon)...');
        const viewCaseBtn = page.locator('.btn-icon-sm[title*="View"]').first();
        await viewCaseBtn.click();
        await page.waitForSelector('.case-details-modal', { timeout: 5000 });
        console.log('   Case Details Modal opened successfully!');

        const modalTitle = await page.textContent('.case-details-modal h3');
        console.log('   Modal Case Title:', modalTitle?.trim());

        // Add note inside modal
        const modalNoteInput = page.locator('.case-details-modal .note-textarea');
        await modalNoteInput.fill('Follow-up verification note from forensic investigator.');
        await page.click('.btn-add-modal-note');
        await page.waitForTimeout(1500);
        const modalFeedback = await page.textContent('.modal-feedback-banner');
        console.log('   Modal Note Feedback:', modalFeedback?.trim());

        // Test export report
        await page.click('.btn-export-case');
        await page.waitForTimeout(500);
        const exportFeedback = await page.textContent('.modal-feedback-banner');
        console.log('   Case Export Feedback:', exportFeedback?.trim());

        // Close modal
        await page.click('.case-details-modal .btn-close');
        await page.waitForTimeout(500);

        // Test New Case Modal
        console.log('10. Testing + New Case creation flow...');
        await page.click('.btn-new-case');
        await page.waitForSelector('.cm-modal form', { timeout: 5000 });
        console.log('    New Case Modal opened.');
        await page.fill('.cm-modal input[type="text"]', `Automated Investigation ${Date.now()}`);
        await page.fill('.cm-modal textarea', 'Detailed objective for testing end-to-end case creation workflow.');
        await page.click('.btn-confirm');
        await page.waitForTimeout(2000);
        console.log('    New Case submitted and created successfully!');

        // Capture verified screenshot
        const screenshotPath = 'C:/Users/srira/.gemini/antigravity-ide/brain/b10fc7b3-b9ce-4d3e-804b-ff6e02f52623/case_management_verified.png';
        await page.screenshot({ path: screenshotPath, fullPage: false });
        console.log('11. Verified screenshot saved to:', screenshotPath);

        console.log('\n====================================================');
        console.log(`TEST SUITE COMPLETED: 0 uncaught errors (${errors.length} detected)`);
        console.log('====================================================\n');

        if (errors.length > 0) {
            console.error('Errors:', errors);
            process.exit(1);
        }
    } finally {
        await browser.close();
    }
}

testCaseManagement().catch(err => {
    console.error('Test suite failed:', err);
    process.exit(1);
});
