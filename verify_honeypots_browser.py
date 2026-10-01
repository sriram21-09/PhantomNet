import sys
import os
import asyncio
from playwright.async_api import async_playwright

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from middleware.auth import create_access_token

VIEWPORTS_TO_TEST = [
    {"name": "desktop_1920x1080", "width": 1920, "height": 1080},
    {"name": "laptop_1440x900", "width": 1440, "height": 900},
    {"name": "desktop_1366x768", "width": 1366, "height": 768},
    {"name": "laptop_1024x768", "width": 1024, "height": 768},
    {"name": "tablet_768x1024", "width": 768, "height": 1024},
    {"name": "mobile_480x900", "width": 480, "height": 900},
    {"name": "mobile_390x844", "width": 390, "height": 844},
    {"name": "mobile_360x800", "width": 360, "height": 800},
]

async def verify_honeypots_browser_hardened():
    artifact_dir = os.getenv(
        "ARTIFACT_DIR",
        r"C:\Users\srira\.gemini\antigravity-ide\brain\a2c4fb30-4cb0-4530-967b-3ca73f14a4cd"
    )
    os.makedirs(artifact_dir, exist_ok=True)

    token = create_access_token({"sub": "admin", "role": "Admin"})
    console_errors = []
    page_errors = []
    api_requests = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1440, "height": 900})

        # Pre-authenticate via session cookie
        await context.add_cookies([
            {
                "name": "phantomnet_access_token",
                "value": token,
                "domain": "localhost",
                "path": "/",
                "httpOnly": True,
                "sameSite": "Strict",
            }
        ])

        page = await context.new_page()

        # Listen to console & unhandled errors
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.on("request", lambda req: api_requests.append(req.url) if "/api/honeypots" in req.url else None)

        print("[1] Navigating directly to authenticated route /honeypots...")
        await page.goto("http://localhost:3000/honeypots", wait_until="domcontentloaded")
        await page.wait_for_selector(".honeypots-title", timeout=10000)
        # Wait for API fetch to complete and real cards to render (replacing skeletons)
        await page.wait_for_selector(".honeypot-card:not(.skeleton)", timeout=15000)

        # ── 1. Page Header & Telemetry ──
        title_el = await page.wait_for_selector(".honeypots-title", timeout=5000)
        title = await title_el.inner_text()
        subtitle = await page.inner_text(".honeypots-subtitle")
        telemetry_badge = await page.inner_text(".header-telemetry-badge")
        print(f"    Page Title: {title}")
        print(f"    Page Subtitle: {subtitle}")
        print(f"    Telemetry: {telemetry_badge.replace(chr(10), ' ')}")
        assert "Honeypot Network" in title
        assert "AUTO-REFRESH" in telemetry_badge.upper() and "5S" in telemetry_badge.upper()

        # ── 2. KPI Summary Strip (4 Cards) ──
        kpi_cards = await page.query_selector_all(".kpi-card")
        print(f"\n[2] Found {len(kpi_cards)} KPI summary cards")
        assert len(kpi_cards) == 4
        for kc in kpi_cards:
            kpi_text = (await kc.inner_text()).replace("\n", ": ")
            print(f"    -> KPI: {kpi_text}")
        assert "ACTIVE NODES" in await page.inner_text(".honeypots-kpi-strip")
        assert "TOTAL HONEYPOTS" in await page.inner_text(".honeypots-kpi-strip")
        assert "TOTAL CAPTURED EVENTS" in await page.inner_text(".honeypots-kpi-strip")

        # ── 3. Operational Honeypot Cards ──
        cards = await page.query_selector_all(".honeypot-card:not(.skeleton)")
        print(f"\n[3] Found {len(cards)} operational honeypot cards")
        assert len(cards) == 4

        expected_ports = {
            "SSH": {"external": "2722", "internal": "2222"},
            "HTTP": {"external": "8080", "internal": "8080"},
            "FTP": {"external": "2721", "internal": "2121"},
            "SMTP": {"external": "2725", "internal": "2525"},
        }

        for card in cards:
            card_title = await (await card.query_selector(".card-title")).inner_text()
            node_id = await (await card.query_selector(".node-id-pill")).inner_text()
            status_text = await (await card.query_selector(".status-text")).inner_text()
            ext_port = await (await card.query_selector(".port-val.host-port")).inner_text()
            int_port = await (await card.query_selector(".port-val.internal-port")).inner_text()
            proto_name = await (await card.query_selector(".proto-name")).inner_text()
            captured = await (await card.query_selector(".telemetry-col:first-child .strip-val")).inner_text()
            target_host = await (await card.query_selector(".target-val")).inner_text()

            print(f"    -> {card_title} ({node_id}) | Protocol: {proto_name} | Status: {status_text}")
            print(f"       External Port: {ext_port} | Internal Port: {int_port}")
            print(f"       Captured Events: {captured} | Target: {target_host}")

            assert proto_name in expected_ports
            assert ext_port == expected_ports[proto_name]["external"]
            assert int_port == expected_ports[proto_name]["internal"]
            assert status_text == "ACTIVE"
            assert int(captured) > 0

        # Save main verified desktop screenshot
        desktop_screenshot = os.path.join(artifact_dir, "honeypots_soc_console_1440.png")
        await page.screenshot(path=desktop_screenshot, full_page=True)
        print(f"    Saved desktop screenshot to: {desktop_screenshot}")

        # ── 4. Interactive Search Filtering ──
        print("\n[4] Testing Search Operations...")
        search_input = await page.query_selector(".search-input")
        await search_input.fill("SSH")
        await page.wait_for_timeout(300)
        filtered_cards = await page.query_selector_all(".honeypot-card:not(.skeleton)")
        match_counter = await (await page.query_selector(".match-counter")).inner_text()
        print(f"    Search 'SSH' -> {len(filtered_cards)} card visible ({match_counter})")
        assert len(filtered_cards) == 1
        assert "SSH" in await (await filtered_cards[0].query_selector(".card-title")).inner_text()

        # Clear search
        await page.click(".clear-search-btn")
        await page.wait_for_timeout(300)
        all_cards = await page.query_selector_all(".honeypot-card:not(.skeleton)")
        print(f"    Cleared search -> {len(all_cards)} cards visible")
        assert len(all_cards) == 4

        # Search by port
        await search_input.fill("2725")
        await page.wait_for_timeout(300)
        smtp_cards = await page.query_selector_all(".honeypot-card:not(.skeleton)")
        print(f"    Search by port '2725' -> {len(smtp_cards)} card visible")
        assert len(smtp_cards) == 1
        assert "SMTP" in await (await smtp_cards[0].query_selector(".card-title")).inner_text()
        await page.click(".clear-search-btn")
        await page.wait_for_timeout(200)

        # ── 5. Status Filter Operations ──
        print("\n[5] Testing Status Filter Operations...")
        await page.select_option(".filter-select", "INACTIVE")
        await page.wait_for_timeout(300)
        empty_state = await page.query_selector(".honeypots-empty-state")
        assert empty_state is not None
        empty_msg = (await empty_state.inner_text()).replace("\n", " ")
        print(f"    Status 'INACTIVE' empty state: {empty_msg}")
        assert "No honeypots match the current filters" in empty_msg

        # Reset filter
        await page.click(".empty-reset-btn")
        await page.wait_for_timeout(300)
        reset_cards = await page.query_selector_all(".honeypot-card:not(.skeleton)")
        print(f"    Reset filter -> {len(reset_cards)} cards restored")
        assert len(reset_cards) == 4

        # ── 6. Manual Refresh ──
        print("\n[6] Testing Refresh Mechanism...")
        req_count_before = len(api_requests)
        await page.click(".refresh-btn")
        await page.wait_for_timeout(500)
        telemetry_after = await page.inner_text(".header-telemetry-badge")
        print(f"    Refreshed Telemetry: {telemetry_after.replace(chr(10), ' ')}")
        assert len(api_requests) > req_count_before

        # ── 7. Detail Inspection Modal & Accessibility ──
        print("\n[7] Testing Detail Modal & Accessibility...")
        first_card_btn = await page.query_selector(".honeypot-card:first-child .card-detail-btn")
        await first_card_btn.click()
        await page.wait_for_timeout(400)

        modal = await page.query_selector(".honeypot-modal")
        assert modal is not None
        modal_title = await (await modal.query_selector(".modal-title")).inner_text()
        modal_desc = await (await modal.query_selector(".modal-desc")).inner_text()
        print(f"    Modal Title: {modal_title}")
        print(f"    Modal Description: {modal_desc}")

        sections = await modal.query_selector_all(".modal-section")
        print(f"    Modal Sections Count: {len(sections)}")
        assert len(sections) >= 4
        for s in sections:
            s_title = await (await s.query_selector(".section-title")).inner_text()
            print(f"       -> {s_title}")

        # Check body scroll lock
        body_overflow = await page.evaluate("() => document.body.style.overflow")
        print(f"    Body overflow locked: {body_overflow == 'hidden'}")
        assert body_overflow == "hidden"

        # Check focus inside modal
        is_focus_in_modal = await page.evaluate(
            "() => !!document.querySelector('.honeypot-modal')?.contains(document.activeElement)"
        )
        print(f"    Focus inside modal: {is_focus_in_modal}")
        assert is_focus_in_modal

        # Capture modal screenshot
        modal_screenshot = os.path.join(artifact_dir, "honeypots_modal_inspection.png")
        await page.screenshot(path=modal_screenshot)
        print(f"    Saved modal screenshot to: {modal_screenshot}")

        # Test Keyboard Escape to close modal
        await page.keyboard.press("Escape")
        await page.wait_for_timeout(300)
        modal_after_esc = await page.query_selector(".honeypot-modal")
        print(f"    Modal closed via Escape: {modal_after_esc is None}")
        assert modal_after_esc is None
        body_overflow_restored = await page.evaluate("() => document.body.style.overflow")
        assert body_overflow_restored in ("", "unset")

        # ── 8. Responsive Layout Verification (All 8 Viewports) ──
        print("\n[8] Testing Responsive Viewports (All 8)...")
        for vp in VIEWPORTS_TO_TEST:
            await page.set_viewport_size({"width": vp["width"], "height": vp["height"]})
            await page.wait_for_timeout(300)
            
            # Check horizontal overflow
            has_overflow = await page.evaluate("() => document.documentElement.scrollWidth > document.documentElement.clientWidth")
            vp_screenshot = os.path.join(artifact_dir, f"honeypots_viewport_{vp['name']}.png")
            await page.screenshot(path=vp_screenshot)
            print(f"    Viewport {vp['name']} ({vp['width']}x{vp['height']}): Overflow={has_overflow} | Saved: {vp_screenshot}")
            assert not has_overflow, f"Horizontal overflow detected at {vp['name']}"

        # ── 9. Error State & Recovery Simulation (State C) ──
        print("\n[9] Testing API Error State & Recovery (State C)...")
        error_context = await browser.new_context()
        await error_context.add_cookies([
            {
                "name": "phantomnet_access_token",
                "value": token,
                "domain": "localhost",
                "path": "/",
                "httpOnly": True,
                "sameSite": "Strict",
            }
        ])
        error_page = await error_context.new_page()
        # Route specifically /api/honeypots to simulate 500 error
        await error_page.route("**/api/honeypots", lambda route: route.fulfill(status=500, body="Internal Server Error"))
        await error_page.goto("http://localhost:3000/honeypots", wait_until="networkidle")
        await error_page.wait_for_selector(".honeypots-error-banner", timeout=10000)
        banner_text = await error_page.inner_text(".honeypots-error-banner")
        print(f"    Error Banner: {banner_text.replace(chr(10), ' ')}")
        assert "Telemetry Alert" in banner_text
        retry_btn = await error_page.query_selector(".error-btn.retry")
        assert retry_btn is not None
        await error_context.close()

        # ── 10. Auth Expiration Simulation (State D) ──
        print("\n[10] Testing Auth Expiration State (State D)...")
        auth_context = await browser.new_context()
        await auth_context.add_cookies([
            {
                "name": "phantomnet_access_token",
                "value": token,
                "domain": "localhost",
                "path": "/",
                "httpOnly": True,
                "sameSite": "Strict",
            }
        ])
        auth_page = await auth_context.new_page()
        # Route specifically /api/honeypots to simulate 401 Unauthorized during session
        await auth_page.route("**/api/honeypots", lambda route: route.fulfill(status=401, body="Unauthorized"))
        await auth_page.goto("http://localhost:3000/honeypots", wait_until="networkidle")
        await auth_page.wait_for_selector(".honeypots-error-banner", timeout=10000)
        auth_banner_text = await auth_page.inner_text(".honeypots-error-banner")
        print(f"    Auth Expiry Banner: {auth_banner_text.replace(chr(10), ' ')}")
        assert "session has expired" in auth_banner_text
        signin_btn = await auth_page.query_selector(".error-btn.auth")
        assert signin_btn is not None
        await auth_context.close()

        # ── 11. Empty Database State (State E) ──
        print("\n[11] Testing Empty Database State (State E)...")
        empty_db_context = await browser.new_context()
        await empty_db_context.add_cookies([
            {
                "name": "phantomnet_access_token",
                "value": token,
                "domain": "localhost",
                "path": "/",
                "httpOnly": True,
                "sameSite": "Strict",
            }
        ])
        empty_db_page = await empty_db_context.new_page()
        await empty_db_page.route("**/api/honeypots", lambda route: route.fulfill(status=200, content_type="application/json", body="[]"))
        await empty_db_page.goto("http://localhost:3000/honeypots", wait_until="networkidle")
        await empty_db_page.wait_for_selector(".honeypots-empty-state.empty-db", timeout=10000)
        empty_db_text = await empty_db_page.inner_text(".honeypots-empty-state.empty-db")
        print(f"    Empty DB State: {empty_db_text.replace(chr(10), ' ')}")
        assert "No Honeypot Nodes Registered" in empty_db_text
        await empty_db_context.close()

        # ── 12. Console & Network Cleanliness ──
        print("\n[12] Checking Console & Network Cleanliness...")
        print(f"    Console errors logged: {len(console_errors)}")
        print(f"    Page exceptions logged: {len(page_errors)}")
        assert len(console_errors) == 0, f"Unexpected console errors: {console_errors}"
        assert len(page_errors) == 0, f"Unexpected page exceptions: {page_errors}"

        print("\n[+] ALL FINAL FORENSIC & UI/UX CHECKS PASSED EMPIRICALLY!")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(verify_honeypots_browser_hardened())
