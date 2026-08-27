# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: playbook.spec.ts >> Sentinel Cross-Browser Validation >> should display playbook cards or a valid empty/loading state
- Location: tests\e2e\playbook.spec.ts:60:3

# Error details

```
Error: expect(received).toBeGreaterThan(expected)

Expected: > 0
Received:   0
```

# Page snapshot

```yaml
- generic [ref=e3]:
  - navigation [ref=e4]:
    - generic [ref=e5]:
      - link "PhantomNet" [ref=e6] [cursor=pointer]:
        - /url: /
      - generic [ref=e11]:
        - link "Dashboard" [ref=e12] [cursor=pointer]:
          - /url: /dashboard
        - button "Monitoring" [ref=e17] [cursor=pointer]
        - button "Intelligence" [ref=e24] [cursor=pointer]
        - button "System" [ref=e31] [cursor=pointer]
      - generic "Switch to light mode" [ref=e37] [cursor=pointer]: Light Mode
  - generic [ref=e43]:
    - generic [ref=e44]:
      - generic [ref=e45]:
        - generic [ref=e46]: SENTINEL_ENGINE_V1.0
        - generic "Click to toggle mock status" [ref=e47] [cursor=pointer]: "AI: Offline"
      - heading "Sentinel Dashboard" [level=1] [ref=e48]
      - paragraph [ref=e49]: AUTONOMOUS THREAT DETECTION & RESPONSE COMMAND CENTER
    - generic [ref=e50]:
      - generic [ref=e51]:
        - generic [ref=e53]: "ENGINE STATUS:"
        - generic [ref=e54]: ONLINE
      - generic [ref=e55]:
        - generic [ref=e57]: "AI PIPELINE:"
        - generic [ref=e58]: CHECKING
      - generic [ref=e59]:
        - generic [ref=e60]: "UPTIME:"
        - generic [ref=e61]: ONLINE
      - generic [ref=e62]:
        - generic [ref=e63]: "RULES LOADED:"
        - generic [ref=e64]: "0"
      - generic [ref=e65]:
        - generic [ref=e66]: "LAST SCAN:"
        - generic [ref=e67]: —
    - generic [ref=e68]:
      - button "Playbooks List" [active] [ref=e69] [cursor=pointer]
      - button "ATT&CK Coverage" [ref=e72] [cursor=pointer]
      - button "Campaign Timeline" [ref=e75] [cursor=pointer]
      - button "Export History Logs" [ref=e78] [cursor=pointer]
    - generic [ref=e81]:
      - generic [ref=e82]:
        - generic [ref=e85]:
          - generic [ref=e91]: "0"
          - generic [ref=e92]:
            - heading "Playbooks Generated" [level=4] [ref=e93]
            - paragraph [ref=e94]: TOTAL PIPELINE OUTPUT
        - generic [ref=e99]:
          - generic [ref=e105]: "0"
          - generic [ref=e106]:
            - heading "Pending Review" [level=4] [ref=e107]
            - paragraph [ref=e108]: AWAITING ANALYST APPROVAL
        - generic [ref=e112]:
          - generic [ref=e118]: "0"
          - generic [ref=e119]:
            - heading "Approved Playbooks" [level=4] [ref=e120]
            - paragraph [ref=e121]: READY FOR DEPLOYMENT
        - generic [ref=e125]:
          - generic [ref=e131]: "0"
          - generic [ref=e132]:
            - heading "Rejected Playbooks" [level=4] [ref=e133]
            - paragraph [ref=e134]: FLAGGED AND ARCHIVED
      - generic [ref=e136]:
        - generic [ref=e137]:
          - generic [ref=e138]:
            - heading "Severity Distribution" [level=4] [ref=e139]
            - paragraph [ref=e140]: NO ACTIVE PLAYBOOKS
          - img [ref=e142]:
            - generic [ref=e145] [cursor=pointer]
            - generic [ref=e146] [cursor=pointer]
            - generic [ref=e147] [cursor=pointer]
            - generic [ref=e148] [cursor=pointer]
            - generic [ref=e149]: "0"
            - generic [ref=e150]: RULES
          - generic [ref=e151]:
            - generic [ref=e152] [cursor=pointer]:
              - generic [ref=e154]: critical
              - generic [ref=e155]: "0"
            - generic [ref=e156] [cursor=pointer]:
              - generic [ref=e158]: high
              - generic [ref=e159]: "0"
            - generic [ref=e160] [cursor=pointer]:
              - generic [ref=e162]: medium
              - generic [ref=e163]: "0"
            - generic [ref=e164] [cursor=pointer]:
              - generic [ref=e166]: low
              - generic [ref=e167]: "0"
        - generic [ref=e168]:
          - generic [ref=e169]:
            - heading "Analyst Approval Rate" [level=4] [ref=e170]
            - paragraph [ref=e171]: PIPELINE EFFICIENCY RATING
          - img [ref=e173]:
            - generic [ref=e176]: 0%
            - generic [ref=e177]: APPROVED RATIO
          - generic [ref=e178]:
            - generic [ref=e179]:
              - generic [ref=e180]: "0"
              - generic [ref=e181]: APPROVED
            - generic [ref=e182]:
              - generic [ref=e183]: "0"
              - generic [ref=e184]: REJECTED
            - generic [ref=e185]:
              - generic [ref=e186]: "0"
              - generic [ref=e187]: PENDING
        - generic [ref=e188]:
          - generic [ref=e189]:
            - heading "Generation Timeline" [level=4] [ref=e190]
            - paragraph [ref=e191]: NO HISTORY RECORDED
          - generic [ref=e192]:
            - img [ref=e193]:
              - generic [ref=e194]: "4"
              - generic [ref=e196]: "3"
              - generic [ref=e198]: "2"
              - generic [ref=e200]: "1"
              - generic [ref=e202]: "0"
            - generic [ref=e204]:
              - generic [ref=e205]: NO_GENERATION_HISTORY
              - paragraph [ref=e206]: Generate playbook response rules to view creation trends.
    - generic [ref=e207]:
      - generic [ref=e208]:
        - heading "ATT&CK Techniques" [level=2] [ref=e209]
        - generic [ref=e210]: 12 MAPPED
      - generic [ref=e211]:
        - generic [ref=e212]:
          - generic:
            - generic: Password Guessing
            - generic: Credential Access
          - link "T1110.001" [ref=e213] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1110/001/
        - generic [ref=e218]:
          - generic:
            - generic: Spearphishing Attachment
            - generic: Initial Access
          - link "T1566.001" [ref=e219] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1566/001/
        - generic [ref=e224]:
          - generic:
            - generic: PowerShell
            - generic: Execution
          - link "T1059.001" [ref=e225] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1059/001/
        - generic [ref=e230]:
          - generic:
            - generic: Scheduled Task
            - generic: Persistence
          - link "T1053.005" [ref=e231] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1053/005/
        - generic [ref=e236]:
          - generic:
            - generic: File and Directory Discovery
            - generic: Discovery
          - link "T1083" [ref=e237] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1083/
        - generic [ref=e242]:
          - generic:
            - generic: SMB/Windows Admin Shares
            - generic: Lateral Movement
          - link "T1021.002" [ref=e243] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1021/002/
        - generic [ref=e248]:
          - generic:
            - generic: DNS
            - generic: Command and Control
          - link "T1071.004" [ref=e249] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1071/004/
        - generic [ref=e254]:
          - generic:
            - generic: Exfiltration Over C2
            - generic: Exfiltration
          - link "T1048.003" [ref=e255] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1048/003/
        - generic [ref=e260]:
          - generic:
            - generic: File Deletion
            - generic: Defense Evasion
          - link "T1070.004" [ref=e261] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1070/004/
        - generic [ref=e266]:
          - generic:
            - generic: Exploitation for Privilege Escalation
            - generic: Privilege Escalation
          - link "T1068" [ref=e267] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1068/
        - generic [ref=e272]:
          - generic:
            - generic: Data Encrypted for Impact
            - generic: Impact
          - link "T1486" [ref=e273] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1486/
        - generic [ref=e278]:
          - generic:
            - generic: Automated Collection
            - generic: Collection
          - link "T1119" [ref=e279] [cursor=pointer]:
            - /url: https://attack.mitre.org/techniques/T1119/
    - generic [ref=e284]:
      - generic [ref=e285]:
        - heading "Detection Rules" [level=2] [ref=e286]
        - generic [ref=e287]: SNORT / SIGMA
      - generic [ref=e288]:
        - generic [ref=e289]:
          - tablist "Rule syntax selection" [ref=e290]:
            - tab "Snort" [selected] [ref=e291] [cursor=pointer]
            - tab "Sigma" [ref=e295] [cursor=pointer]
          - button "Copy" [ref=e299] [cursor=pointer]
        - generic [ref=e303]:
          - generic [ref=e304]:
            - generic [ref=e305]: "1"
            - generic [ref=e306]: alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT Possible SMB Brute Force"; flow:to_server,established; content:"|ff|SMB"; depth:4; content:"|73 00 00 00|"; distance:0; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:2024001; rev:3; )
          - generic [ref=e307]: "2"
          - generic [ref=e309]:
            - generic [ref=e310]: "3"
            - generic [ref=e311]: "# Secondary detection for lateral movement"
          - generic [ref=e312]:
            - generic [ref=e313]: "4"
            - generic [ref=e314]: alert tcp $HOME_NET any -> $HOME_NET 135 (msg:"INTERNAL Lateral Movement via DCOM"; flow:to_server,established; content:"|05|"; depth:1; content:"|0b|"; distance:1; within:1; classtype:attempted-admin; sid:2024002; rev:1; )
        - generic [ref=e315]:
          - generic [ref=e316]: Snort IDS Rule
          - generic [ref=e317]: 4 lines
    - generic [ref=e318]:
      - generic [ref=e319]:
        - heading "Generated Playbooks" [level=2] [ref=e320]
        - generic [ref=e321]: 0 PLAYBOOKS
      - generic [ref=e322]:
        - button "All 0" [ref=e323] [cursor=pointer]:
          - text: All
          - generic [ref=e324]: "0"
        - button "Draft 0" [ref=e325] [cursor=pointer]:
          - text: Draft
          - generic [ref=e326]: "0"
        - button "Approved 0" [ref=e327] [cursor=pointer]:
          - text: Approved
          - generic [ref=e328]: "0"
        - button "Rejected 0" [ref=e329] [cursor=pointer]:
          - text: Rejected
          - generic [ref=e330]: "0"
      - generic [ref=e331]:
        - textbox "SEARCH PLAYBOOKS..." [ref=e333]
        - generic [ref=e334]:
          - generic [ref=e335]: "SEVERITY:"
          - combobox [ref=e336] [cursor=pointer]:
            - option "ALL SEVERITIES" [selected]
            - option "CRITICAL"
            - option "HIGH"
            - option "MEDIUM"
            - option "LOW"
        - generic [ref=e337]:
          - generic [ref=e338]: "STATUS:"
          - combobox [ref=e339] [cursor=pointer]:
            - option "ALL STATUSES" [selected]
            - option "DRAFT"
            - option "APPROVED"
            - option "REJECTED"
        - generic [ref=e340]:
          - generic [ref=e341]: "TECHNIQUE:"
          - combobox [ref=e342] [cursor=pointer]:
            - option "ALL TECHNIQUES" [selected]
            - option "T1110.001 - Password Guessing"
            - option "T1566.001 - Spearphishing Attachment"
            - option "T1059.001 - PowerShell"
            - option "T1053.005 - Scheduled Task"
            - option "T1083 - File and Directory Discovery"
            - option "T1021.002 - SMB/Windows Admin Shares"
            - option "T1071.004 - DNS"
            - option "T1048.003 - Exfiltration Over C2"
            - option "T1070.004 - File Deletion"
            - option "T1068 - Exploitation for Privilege Escalation"
            - option "T1486 - Data Encrypted for Impact"
            - option "T1119 - Automated Collection"
      - generic [ref=e343]:
        - heading "System Connection Failure" [level=3] [ref=e346]
        - paragraph [ref=e347]: "Failed to execute 'json' on 'Response': Unexpected end of JSON input"
        - button "Retry Connection" [ref=e348] [cursor=pointer]
    - generic "Notifications":
      - alert [ref=e351]:
        - generic [ref=e352]:
          - generic [ref=e355]:
            - strong [ref=e356]: Connection Failed
            - generic [ref=e357]: "Failed to execute 'json' on 'Response': Unexpected end of JSON input"
          - button "Dismiss notification" [ref=e358] [cursor=pointer]
      - alert [ref=e361]:
        - generic [ref=e362]:
          - generic [ref=e365]:
            - strong [ref=e366]: Matrix Load Failed
            - generic [ref=e367]: "Failed to execute 'json' on 'Response': Unexpected end of JSON input"
          - button "Dismiss notification" [ref=e368] [cursor=pointer]
      - alert [ref=e371]:
        - generic [ref=e372]:
          - generic [ref=e375]:
            - strong [ref=e376]: Connection Failed
            - generic [ref=e377]: "Failed to execute 'json' on 'Response': Unexpected end of JSON input"
          - button "Dismiss notification" [ref=e378] [cursor=pointer]
      - alert [ref=e381]:
        - generic [ref=e382]:
          - generic [ref=e385]:
            - strong [ref=e386]: Matrix Load Failed
            - generic [ref=e387]: "Failed to execute 'json' on 'Response': Unexpected end of JSON input"
          - button "Dismiss notification" [ref=e388] [cursor=pointer]
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
  57  |     ).toBeVisible({ timeout: 12000 });
  58  |   });
  59  | 
  60  |   test("should display playbook cards or a valid empty/loading state", async ({ page }) => {
  61  |     const cards = await page.locator(".playbook-card").count();
  62  |     const empty = await page.locator(".sentinel-empty-state").count();
  63  |     const loading = await page.locator(".playbook-skeleton-card").count();
> 64  |     expect(cards + empty + loading).toBeGreaterThan(0);
      |                                     ^ Error: expect(received).toBeGreaterThan(expected)
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
  158 |   // Flexbox layout validation
  159 |   test("should have correct flex layout for viewer header (no overflow)", async ({ page }) => {
  160 |     const cards = page.locator(".playbook-card");
  161 |     if ((await cards.count()) === 0) { test.skip(); return; }
  162 | 
  163 |     await cards.first().click();
  164 |     await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
```