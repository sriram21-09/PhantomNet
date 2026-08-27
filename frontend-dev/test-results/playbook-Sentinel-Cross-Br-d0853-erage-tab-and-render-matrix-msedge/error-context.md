# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: playbook.spec.ts >> Sentinel Cross-Browser Validation >> should switch to ATT&CK Coverage tab and render matrix
- Location: tests\e2e\playbook.spec.ts:53:3

# Error details

```
Error: expect(locator).toBeVisible() failed

Locator: locator('.mitre-matrix-container, .sentinel-mitre-grid')
Expected: visible
Timeout: 12000ms
Error: element(s) not found

Call log:
  - Expect "toBeVisible" with timeout 12000ms
  - waiting for locator('.mitre-matrix-container, .sentinel-mitre-grid')

```

```yaml
- navigation:
  - link "PhantomNet":
    - /url: /
    - img
    - text: PhantomNet
  - link "Dashboard":
    - /url: /dashboard
    - img
    - text: Dashboard
  - button "Monitoring":
    - img
    - text: Monitoring
    - img
  - button "Intelligence":
    - img
    - text: Intelligence
    - img
  - button "System":
    - img
    - text: System
    - img
  - img
  - text: Light Mode
- text: "SENTINEL_ENGINE_V1.0 AI: Offline"
- heading "Sentinel Dashboard" [level=1]
- paragraph: AUTONOMOUS THREAT DETECTION & RESPONSE COMMAND CENTER
- text: "ENGINE STATUS: ONLINE AI PIPELINE: CHECKING UPTIME: ONLINE RULES LOADED: 0 LAST SCAN: —"
- button "Playbooks List":
  - img
  - text: Playbooks List
- button "ATT&CK Coverage":
  - img
  - text: ATT&CK Coverage
- button "Campaign Timeline":
  - img
  - text: Campaign Timeline
- button "Export History Logs":
  - img
  - text: Export History Logs
- heading "MITRE ATT&CK Matrix Heatmap" [level=2]
- text: LIVE COVERAGE
- img
- heading "Matrix Connection Failure" [level=3]
- paragraph: "Failed to execute 'json' on 'Response': Unexpected end of JSON input"
- button "Retry Loading Matrix":
  - img
  - text: Retry Loading Matrix
```

# Test source

```ts
  1   | import { test, expect, Page } from "@playwright/test";
  2   | 
  3   | /**
  4   |  * Cross-browser E2E tests for the Sentinel Dashboard.
  5   |  *
  6   |  * Runs against the LIVE dev server (localhost:5173) with the real
  7   |  * backend API (localhost:8000). No page.route() mocks are used here
  8   |  * because the Vite dev-server Proxy forwards /api/ at the server level
  9   |  * and browser-level mocks are skipped when the backend serves data.
  10  |  *
  11  |  * Tested: Chromium, Firefox, Microsoft Edge.
  12  |  */
  13  | 
  14  | async function navigateToPlaybooksList(page: Page) {
  15  |   await page.goto("http://localhost:5173/sentinel");
  16  |   // Wait for React to hydrate (h1 confirms JS loaded)
  17  |   await page.waitForSelector("h1", { timeout: 20000 });
  18  |   // Click Playbooks List tab for consistent start state
  19  |   const tabBtn = page.locator(".nav-tab-btn", { hasText: "Playbooks List" });
  20  |   await tabBtn.waitFor({ state: "visible", timeout: 10000 });
  21  |   await tabBtn.click();
  22  |   // Wait for either playbook cards, empty state, or loading skeletons to appear
  23  |   await page.waitForSelector(".sentinel-tabs-container", { timeout: 15000 });
  24  | }
  25  | 
  26  | test.describe("Sentinel Cross-Browser Validation", () => {
  27  |   test.beforeEach(async ({ page }) => {
  28  |     await navigateToPlaybooksList(page);
  29  |   });
  30  | 
  31  |   // Layout Tests
  32  |   test("should render dashboard with heading and nav tabs", async ({ page }) => {
  33  |     await expect(page.locator("h1")).toBeVisible();
  34  |     await expect(page.locator("h1")).toContainText("Sentinel");
  35  |     await expect(page.locator(".sentinel-nav-tabs")).toBeVisible();
  36  |     await expect(page.locator(".nav-tab-btn", { hasText: "Playbooks List" })).toBeVisible();
  37  |     await expect(page.locator(".nav-tab-btn", { hasText: "ATT&CK Coverage" })).toBeVisible();
  38  |   });
  39  | 
  40  |   test("should show filter tabs in the playbooks view", async ({ page }) => {
  41  |     const tabs = page.locator(".sentinel-tabs-container");
  42  |     await expect(tabs).toBeVisible();
  43  |     await expect(tabs.locator("button", { hasText: /All/ })).toBeVisible();
  44  |     await expect(tabs.locator("button", { hasText: /Draft/ })).toBeVisible();
  45  |     await expect(tabs.locator("button", { hasText: /Approved/ })).toBeVisible();
  46  |   });
  47  | 
  48  |   test("should show search and filter controls", async ({ page }) => {
  49  |     await expect(page.locator(".hud-search-input")).toBeVisible();
  50  |     await expect(page.locator(".hud-filter-select").first()).toBeVisible();
  51  |   });
  52  | 
  53  |   test("should switch to ATT&CK Coverage tab and render matrix", async ({ page }) => {
  54  |     await page.locator(".nav-tab-btn", { hasText: "ATT&CK Coverage" }).click();
  55  |     await expect(
  56  |       page.locator(".mitre-matrix-container, .sentinel-mitre-grid")
> 57  |     ).toBeVisible({ timeout: 12000 });
      |       ^ Error: expect(locator).toBeVisible() failed
  58  |   });
  59  | 
  60  |   test("should display playbook cards or a valid empty/loading state", async ({ page }) => {
  61  |     const cards = await page.locator(".playbook-card").count();
  62  |     const empty = await page.locator(".sentinel-empty-state").count();
  63  |     const loading = await page.locator(".playbook-skeleton-card").count();
  64  |     expect(cards + empty + loading).toBeGreaterThan(0);
  65  |   });
  66  | 
  67  |   test("should open and close the playbook viewer modal", async ({ page }) => {
  68  |     const cards = page.locator(".playbook-card");
  69  |     if ((await cards.count()) === 0) { test.skip(); return; }
  70  | 
  71  |     await cards.first().click();
  72  |     const modal = page.locator(".playbook-viewer-panel");
  73  |     await expect(modal).toBeVisible({ timeout: 10000 });
  74  |     await expect(page.locator(".pbv-title")).toBeVisible();
  75  | 
  76  |     await page.locator(".pbv-close-btn").click();
  77  |     await expect(modal).not.toBeVisible({ timeout: 5000 });
  78  |   });
  79  | 
  80  |   test("should render viewer tabs and download bar when modal opens", async ({ page }) => {
  81  |     const cards = page.locator(".playbook-card");
  82  |     if ((await cards.count()) === 0) { test.skip(); return; }
  83  | 
  84  |     await cards.first().click();
  85  |     await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
  86  |     await expect(page.locator(".pbv-tab-bar")).toBeVisible();
  87  |     await expect(page.locator(".pbv-download-bar")).toBeVisible();
  88  |     await expect(page.locator("#playbook-viewer-export-btn")).toBeVisible();
  89  |   });
  90  | 
  91  |   // PDF download via export dropdown
  92  |   test("should trigger PDF download via export dropdown", async ({ page }) => {
  93  |     const cards = page.locator(".playbook-card");
  94  |     if ((await cards.count()) === 0) { test.skip(); return; }
  95  | 
  96  |     await cards.first().click();
  97  |     await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
  98  |     await expect(page.locator(".pbv-download-bar")).toBeVisible();
  99  | 
  100 |     await page.locator("#playbook-viewer-export-btn").click();
  101 |     await expect(page.locator(".pbv-export-menu")).toBeVisible({ timeout: 5000 });
  102 | 
  103 |     const [download] = await Promise.all([
  104 |       page.waitForEvent("download", { timeout: 15000 }),
  105 |       page.locator(".pbv-export-item").filter({ hasText: "PDF" }).click(),
  106 |     ]);
  107 |     expect(download.suggestedFilename()).toMatch(/\.pdf$/i);
  108 |   });
  109 | 
  110 |   // Markdown download from download bar
  111 |   test("should trigger Markdown download from download bar", async ({ page }) => {
  112 |     const cards = page.locator(".playbook-card");
  113 |     if ((await cards.count()) === 0) { test.skip(); return; }
  114 | 
  115 |     await cards.first().click();
  116 |     await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
  117 |     await expect(page.locator(".pbv-download-bar")).toBeVisible();
  118 | 
  119 |     const [download] = await Promise.all([
  120 |       page.waitForEvent("download", { timeout: 15000 }),
  121 |       page.locator(".pbv-download-btn").filter({ hasText: "Markdown" }).click(),
  122 |     ]);
  123 |     expect(download.suggestedFilename()).toMatch(/\.md$/i);
  124 |   });
  125 | 
  126 |   // JSON download from download bar
  127 |   test("should trigger JSON download from download bar", async ({ page }) => {
  128 |     const cards = page.locator(".playbook-card");
  129 |     if ((await cards.count()) === 0) { test.skip(); return; }
  130 | 
  131 |     await cards.first().click();
  132 |     await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
  133 |     await expect(page.locator(".pbv-download-bar")).toBeVisible();
  134 | 
  135 |     const [download] = await Promise.all([
  136 |       page.waitForEvent("download", { timeout: 15000 }),
  137 |       page.locator(".pbv-download-btn").filter({ hasText: "JSON" }).click(),
  138 |     ]);
  139 |     expect(download.suggestedFilename()).toMatch(/\.json$/i);
  140 |   });
  141 | 
  142 |   // STIX download from download bar
  143 |   test("should trigger STIX Bundle download from download bar", async ({ page }) => {
  144 |     const cards = page.locator(".playbook-card");
  145 |     if ((await cards.count()) === 0) { test.skip(); return; }
  146 | 
  147 |     await cards.first().click();
  148 |     await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
  149 |     await expect(page.locator(".pbv-download-bar")).toBeVisible();
  150 | 
  151 |     const [download] = await Promise.all([
  152 |       page.waitForEvent("download", { timeout: 15000 }),
  153 |       page.locator(".pbv-download-btn").filter({ hasText: "STIX Bundle" }).click(),
  154 |     ]);
  155 |     expect(download.suggestedFilename()).toMatch(/stix\.json$/i);
  156 |   });
  157 | 
```