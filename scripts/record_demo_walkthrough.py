import os
import sys
import time
import json
from PIL import Image, ImageDraw, ImageFont
import cv2
import numpy as np
from playwright.sync_api import sync_playwright

def create_annotations(frame_np, phase_title, step_caption, highlight_rect=None, step_index=1, total_steps=9):
    """
    Renders HD visual annotations, lower-third phase banner, subtitle caption,
    and pulsing highlight rectangle onto a 1920x1080 frame.
    """
    img = Image.fromarray(cv2.cvtColor(frame_np, cv2.COLOR_BGR2RGB))
    draw = ImageDraw.Draw(img, 'RGBA')
    width, height = img.size

    # Load system fonts with fallbacks
    try:
        font_banner = ImageFont.truetype("arialbd.ttf", 26)
        font_caption = ImageFont.truetype("arial.ttf", 21)
        font_badge = ImageFont.truetype("arialbd.ttf", 18)
    except Exception:
        font_banner = ImageFont.load_default()
        font_caption = ImageFont.load_default()
        font_badge = ImageFont.load_default()

    # 1. Top Bar Header Overlay
    draw.rectangle([(0, 0), (width, 45)], fill=(10, 16, 26, 240))
    draw.text((20, 10), "PHANTOMNET V3 — COMPREHENSIVE DASHBOARD WALKTHROUGH", fill=(0, 229, 255, 255), font=font_badge)

    # Step progress badge
    step_str = f"STEP {step_index} OF {total_steps}"
    draw.rectangle([(width - 160, 8), (width - 20, 36)], fill=(30, 41, 59, 240), outline=(0, 229, 255, 255))
    draw.text((width - 145, 12), step_str, fill=(255, 255, 255, 255), font=font_badge)

    # 2. Lower-Third Phase Banner (Glassmorphism dark card)
    banner_y = height - 125
    draw.rectangle([(30, banner_y), (width - 30, height - 25)], fill=(15, 23, 42, 235), outline=(56, 189, 248, 255), width=2)

    # Phase Title
    draw.text((50, banner_y + 12), phase_title.upper(), fill=(56, 189, 248, 255), font=font_banner)
    # Step Caption / Subtitle
    draw.text((50, banner_y + 48), step_caption, fill=(241, 245, 249, 255), font=font_caption)

    # 3. Optional Highlight Rectangle around target UI elements
    if highlight_rect:
        x1, y1, x2, y2 = highlight_rect
        draw.rectangle([(x1, y1), (x2, y2)], fill=(0, 229, 255, 25), outline=(0, 229, 255, 255), width=3)
        c_len = 15
        draw.line([(x1, y1), (x1 + c_len, y1)], fill=(255, 255, 255, 255), width=4)
        draw.line([(x1, y1), (x1, y1 + c_len)], fill=(255, 255, 255, 255), width=4)
        draw.line([(x2, y2), (x2 - c_len, y2)], fill=(255, 255, 255, 255), width=4)
        draw.line([(x2, y2), (x2, y2 - c_len)], fill=(255, 255, 255, 255), width=4)

    return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

def record_dashboard_walkthrough():
    print("[INFO] Starting PhantomNet V3 Comprehensive Dashboard Walkthrough Recording...")

    frames = []
    fps = 10
    target_width, target_height = 1920, 1080
    base_url = "http://localhost:5173"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={'width': target_width, 'height': target_height},
            device_scale_factor=1.0
        )
        page = context.new_page()

        # Seed mock admin token, user, and welcome seen state into localStorage
        token = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiYWRtaW4iLCAicm9sZSI6ICJBZG1pbiIsICJleHAiOiAxNzg4MzQyNTExfQ.mocktoken"
        user_info = json.dumps({"id": 1, "username": "admin", "email": "admin@phantomnet.io", "role": "Admin"})
        
        page.goto(base_url, wait_until="domcontentloaded")
        page.evaluate(f"localStorage.setItem('admin_token', '{token}'); localStorage.setItem('admin_user', '{user_info}'); localStorage.setItem('phantomnet_welcome_seen', 'true');")

        def dismiss_welcome_modal():
            try:
                welcome_btn = page.locator(".welcome-btn").first
                if welcome_btn.is_visible():
                    welcome_btn.click()
                    page.wait_for_timeout(500)
            except Exception:
                pass

        def capture_frames(duration_sec, phase_title, caption, highlight=None, step_idx=1):
            count = int(duration_sec * fps)
            for _ in range(count):
                screenshot_bytes = page.screenshot(type='png')
                nparr = np.frombuffer(screenshot_bytes, np.uint8)
                img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                if img_np.shape[1] != target_width or img_np.shape[0] != target_height:
                    img_np = cv2.resize(img_np, (target_width, target_height))
                annotated = create_annotations(img_np, phase_title, caption, highlight, step_index=step_idx, total_steps=9)
                frames.append(annotated)
                time.sleep(1.0 / fps)

        # -------------------------------------------------------------
        # PHASE 1: Overview Dashboard
        # -------------------------------------------------------------
        print("[PHASE 1] Recording Overview Dashboard...")
        page.goto(f"{base_url}/dashboard", wait_until="domcontentloaded")
        page.evaluate("localStorage.setItem('phantomnet_welcome_seen', 'true');")
        dismiss_welcome_modal()
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.5,
            phase_title="Phase 1: Overview Operations Dashboard",
            caption="Real-time visibility across active deception mesh nodes, connection velocity, and threat metrics.",
            highlight=[40, 80, 1880, 520],
            step_idx=1
        )

        # -------------------------------------------------------------
        # PHASE 2: Theme Customization (Dark / Light Switch)
        # -------------------------------------------------------------
        print("[PHASE 2] Recording Theme Customization...")
        dismiss_welcome_modal()
        theme_toggle = page.locator(".theme-toggle-pro").first
        if theme_toggle.count() > 0:
            theme_toggle.click(force=True)
            page.wait_for_timeout(1000)

        capture_frames(
            duration_sec=3.0,
            phase_title="Phase 2: Theme Customization (Light Mode)",
            caption="Instant theme toggle between High-Contrast Dark Cyber SOC palette and Clean Light layout.",
            highlight=[1680, 10, 1890, 50],
            step_idx=2
        )

        if theme_toggle.count() > 0:
            theme_toggle.click(force=True)
            page.wait_for_timeout(1000)

        capture_frames(
            duration_sec=2.0,
            phase_title="Phase 2: Dark Cyber SOC Theme Restored",
            caption="Restoring Slate-900 dark theme canvas with glowing emerald status indicators.",
            highlight=[1680, 10, 1890, 50],
            step_idx=2
        )

        # -------------------------------------------------------------
        # PHASE 3: Honeypot Monitors
        # -------------------------------------------------------------
        print("[PHASE 3] Recording Honeypot Monitors...")
        page.goto(f"{base_url}/honeypots", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.5,
            phase_title="Phase 3: Honeypot Deception Mesh Monitors",
            caption="Active deception services: SSH (:2222), HTTP (:8080), FTP (:2121), and SMTP (:2525) capturing payloads.",
            highlight=[40, 90, 1880, 620],
            step_idx=3
        )

        # -------------------------------------------------------------
        # PHASE 4: ML Model Analytics
        # -------------------------------------------------------------
        print("[PHASE 4] Recording ML Model Analytics...")
        page.goto(f"{base_url}/ml-insights", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.5,
            phase_title="Phase 4: ML Model Threat Analytics & 23D Feature Extraction",
            caption="Sub-15ms Isolation Forest + Random Forest ensemble anomaly scoring with SHAP explainability.",
            highlight=[40, 90, 1880, 680],
            step_idx=4
        )

        # -------------------------------------------------------------
        # PHASE 5: Real-Time Event Search & Filtering
        # -------------------------------------------------------------
        print("[PHASE 5] Recording Real-Time Event Search & Filtering...")
        page.goto(f"{base_url}/events", wait_until="domcontentloaded")
        page.wait_for_timeout(1200)
        search_input = page.locator("input[type='text'], input[placeholder*='Search']").first
        if search_input.count() > 0:
            search_input.fill("SSH")
            page.wait_for_timeout(800)

        capture_frames(
            duration_sec=3.5,
            phase_title="Phase 5: Event Stream Keyword Search & Filters",
            caption="Dynamic live filtering across incoming honeypot logs by protocol, IP address, and payload text.",
            highlight=[40, 80, 1880, 250],
            step_idx=5
        )

        # -------------------------------------------------------------
        # PHASE 6: Sentinel Dashboard & ATT&CK Heatmap
        # -------------------------------------------------------------
        print("[PHASE 6] Recording Sentinel Dashboard & MITRE ATT&CK Matrix...")
        page.goto(f"{base_url}/sentinel", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.5,
            phase_title="Phase 6: Sentinel Threat Engine & MITRE ATT&CK Heatmap",
            caption="DBSCAN alert clustering automatically correlates multi-protocol alerts and illuminates ATT&CK tactics.",
            highlight=[40, 90, 1880, 520],
            step_idx=6
        )

        # -------------------------------------------------------------
        # PHASE 7: Playbook Viewer Modal
        # -------------------------------------------------------------
        print("[PHASE 7] Recording Playbook Viewer Modal...")
        view_btn = page.locator(".btn-view-playbook, button:has-text('View Playbook'), .btn-primary-glow").first
        if view_btn.count() > 0:
            view_btn.click(force=True)
            page.wait_for_timeout(1500)

        capture_frames(
            duration_sec=4.0,
            phase_title="Phase 7: Playbook Viewer & Rule Synthesizer",
            caption="Auto-synthesizing Snort SIDs, Sigma YAML rules, and Jinja2 incident response documentation.",
            highlight=[160, 60, 1760, 960],
            step_idx=7
        )

        # Close viewer modal if open
        close_btn = page.locator(".modal-close-btn, button:has-text('Close'), .close-modal").first
        if close_btn.count() > 0:
            close_btn.click(force=True)
            page.wait_for_timeout(800)

        # -------------------------------------------------------------
        # PHASE 8: Multi-Select Batch Approval Workflow
        # -------------------------------------------------------------
        print("[PHASE 8] Recording Multi-Select Batch Approval Workflow...")
        checkboxes = page.locator(".playbook-card-checkbox, input[type='checkbox']")
        count = checkboxes.count()
        if count > 1:
            checkboxes.nth(0).check(force=True)
            checkboxes.nth(1).check(force=True)
            page.wait_for_timeout(800)
        elif count == 1:
            checkboxes.nth(0).check(force=True)
            page.wait_for_timeout(800)
        else:
            select_all = page.locator(".playbook-list-header-checkbox").first
            if select_all.count() > 0:
                select_all.check(force=True)
                page.wait_for_timeout(800)

        capture_frames(
            duration_sec=2.5,
            phase_title="Phase 8: Multi-Select Batch Selection",
            caption="Analysts select multiple pending playbooks to trigger the floating batch action toolbar.",
            highlight=[100, 80, 1820, 800],
            step_idx=8
        )

        batch_approve_btn = page.locator(".btn-batch-approve, button:has-text('Batch Approve')").first
        if batch_approve_btn.count() > 0:
            batch_approve_btn.click(force=True)
            page.wait_for_timeout(1000)

            analyst_input = page.locator("#batch-analyst-name-input, input[placeholder*='analyst']")
            if analyst_input.count() > 0:
                analyst_input.fill("analyst_admin")
                page.wait_for_timeout(500)

            capture_frames(
                duration_sec=3.0,
                phase_title="Phase 8: Batch Approval Authorization Modal",
                caption="Digital signature verification and batch authorization for immediate automated rule deployment.",
                highlight=[450, 200, 1470, 850],
                step_idx=8
            )

            confirm_batch_btn = page.locator(".btn-confirm-approve, button:has-text('Confirm Batch Approve')").first
            if confirm_batch_btn.count() > 0:
                confirm_batch_btn.click(force=True)
                page.wait_for_timeout(1200)

        capture_frames(
            duration_sec=2.0,
            phase_title="Phase 8: Batch Approval State Transition Completed",
            caption="Playbook statuses transition to 'APPROVED' with audit trail signatures recorded.",
            highlight=[100, 80, 1820, 800],
            step_idx=8
        )

        # -------------------------------------------------------------
        # PHASE 9: Admin Settings & Governance
        # -------------------------------------------------------------
        print("[PHASE 9] Recording Admin Settings & Governance...")
        page.goto(f"{base_url}/admin", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.5,
            phase_title="Phase 9: Admin Settings & Security Governance",
            caption="Managing RBAC user roles, system maintenance, audit logs, and security parameters.",
            highlight=[40, 90, 1880, 680],
            step_idx=9
        )

        browser.close()

    print(f"[INFO] Total captured frames: {len(frames)}")

    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos")
    os.makedirs(output_dir, exist_ok=True)

    mp4_path = os.path.join(output_dir, "demo_dashboard_walkthrough.mp4")
    webp_path = os.path.join(output_dir, "demo_dashboard_walkthrough.webp")

    artifact_dir = r"C:\Users\manid\.gemini\antigravity-ide\brain\7352a6a6-93e1-4f57-85fa-be55e31aa7c9"
    artifact_mp4 = os.path.join(artifact_dir, "demo_dashboard_walkthrough.mp4")
    artifact_webp = os.path.join(artifact_dir, "demo_dashboard_walkthrough.webp")

    # 1. Output MP4 using OpenCV VideoWriter
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(mp4_path, fourcc, fps, (target_width, target_height))
    for frame in frames:
        out.write(frame)
    out.release()
    print(f"[OK] Exported MP4 Demo: {mp4_path} ({os.path.getsize(mp4_path)} bytes)")

    if os.path.exists(artifact_dir):
        with open(mp4_path, 'rb') as f_src, open(artifact_mp4, 'wb') as f_dst:
            f_dst.write(f_src.read())
        print(f"[OK] Copied MP4 to Artifacts: {artifact_mp4}")

    # 2. Output Animated WebP preview using Pillow
    print("[INFO] Rendering Animated WebP preview...")
    pil_frames = []
    subsampled = frames[::2]
    for frame in subsampled:
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img_pil = Image.fromarray(rgb).resize((1280, 720), Image.Resampling.LANCZOS)
        pil_frames.append(img_pil)

    if pil_frames:
        pil_frames[0].save(
            webp_path,
            save_all=True,
            append_images=pil_frames[1:],
            duration=int(2000 / fps),
            loop=0
        )
        print(f"[OK] Exported Animated WebP: {webp_path} ({os.path.getsize(webp_path)} bytes)")

        if os.path.exists(artifact_dir):
            with open(webp_path, 'rb') as f_src, open(artifact_webp, 'wb') as f_dst:
                f_dst.write(f_src.read())
            print(f"[OK] Copied Animated WebP to Artifacts: {artifact_webp}")

    print("[SUCCESS] Dashboard Walkthrough Demo Recording Complete!")

if __name__ == "__main__":
    record_dashboard_walkthrough()
