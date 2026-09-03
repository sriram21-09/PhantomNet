import os
import sys
import time
import json
from PIL import Image, ImageDraw, ImageFont
import cv2
import numpy as np
from playwright.sync_api import sync_playwright

def create_annotations(frame_np, phase_title, step_caption, highlight_rect=None, step_index=1, total_steps=8):
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
    draw.text((20, 10), "PHANTOMNET V3 — DEMO 1: END-TO-END AUTOMATED PIPELINE", fill=(0, 229, 255, 255), font=font_badge)

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

def record_pipeline_e2e():
    print("[INFO] Starting PhantomNet V3 End-to-End Pipeline Demo Recording...")

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
                annotated = create_annotations(img_np, phase_title, caption, highlight, step_index=step_idx, total_steps=8)
                frames.append(annotated)
                time.sleep(1.0 / fps)

        # -------------------------------------------------------------
        # STEP 1: Live Attack Simulation & Ingestion
        # -------------------------------------------------------------
        print("[STEP 1] Recording Live Attack Simulation & Ingestion...")
        page.goto(f"{base_url}/dashboard", wait_until="domcontentloaded")
        page.evaluate("localStorage.setItem('phantomnet_welcome_seen', 'true');")
        dismiss_welcome_modal()
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.5,
            phase_title="Step 1: Live Attack Simulation & Honeypot Ingestion",
            caption="Multi-vector attack traffic (SSH Brute Force T1110.001, SQL Injection T1190) hitting active deception mesh.",
            highlight=[40, 80, 1880, 520],
            step_idx=1
        )

        # -------------------------------------------------------------
        # STEP 2: Honeypot Deception Telemetry
        # -------------------------------------------------------------
        print("[STEP 2] Recording Honeypot Deception Telemetry...")
        page.goto(f"{base_url}/honeypots", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.5,
            phase_title="Step 2: Honeypot Deception Service Telemetry",
            caption="Cowrie (:2222) and Dionaea/Web (:8080) trap malicious payloads and stream attacker telemetry to backend.",
            highlight=[40, 90, 1880, 620],
            step_idx=2
        )

        # -------------------------------------------------------------
        # STEP 3: ML Inference & Real-Time Threat Scoring
        # -------------------------------------------------------------
        print("[STEP 3] Recording ML Inference & Threat Scoring...")
        page.goto(f"{base_url}/ml-insights", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=4.0,
            phase_title="Step 3: ML Inference Engine & 23D Threat Scoring",
            caption="Sub-15ms ML classification extracts 23 network features, computing anomaly and threat scores (Score: 94.8, CRITICAL).",
            highlight=[40, 90, 1880, 680],
            step_idx=3
        )

        # -------------------------------------------------------------
        # STEP 4: Incident Clustering & Sentinel Playbook Generation
        # -------------------------------------------------------------
        print("[STEP 4] Recording Incident Clustering & Sentinel Playbook Generation...")
        page.goto(f"{base_url}/sentinel", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.5,
            phase_title="Step 4: DBSCAN Alert Clustering & Playbook Generation",
            caption="DBSCAN correlates attack telemetry across honeypot nodes and auto-generates structured Sentinel IR Playbooks.",
            highlight=[40, 90, 1880, 520],
            step_idx=4
        )

        # -------------------------------------------------------------
        # STEP 5: SOC Analyst Review & Quality Scoring
        # -------------------------------------------------------------
        print("[STEP 5] Recording SOC Analyst Review & Quality Scoring...")
        capture_frames(
            duration_sec=3.5,
            phase_title="Step 5: SOC Analyst Review & ATT&CK Heatmap Coverage",
            caption="Analysts evaluate playbook quality metrics (Score 94/100) and verify MITRE ATT&CK coverage.",
            highlight=[40, 480, 1880, 950],
            step_idx=5
        )

        # -------------------------------------------------------------
        # STEP 6: Deep Playbook Inspection & IDS Rule Synthesis
        # -------------------------------------------------------------
        print("[STEP 6] Recording Deep Playbook Inspection & Detection Rule Synthesis...")
        view_btn = page.locator(".btn-view-playbook, button:has-text('View Playbook'), .btn-primary-glow").first
        if view_btn.count() > 0:
            view_btn.click(force=True)
            page.wait_for_timeout(1500)

        capture_frames(
            duration_sec=4.5,
            phase_title="Step 6: Playbook Inspection & Automated IDS Rule Synthesis",
            caption="Synthesizing Snort SIDs, Sigma YAML rules, and automated containment runbooks from attack signatures.",
            highlight=[160, 60, 1760, 960],
            step_idx=6
        )

        # Close viewer modal if open
        close_btn = page.locator(".modal-close-btn, button:has-text('Close'), .close-modal").first
        if close_btn.count() > 0:
            close_btn.click(force=True)
            page.wait_for_timeout(800)

        # -------------------------------------------------------------
        # STEP 7: One-Click Playbook Approval & Digital Signature
        # -------------------------------------------------------------
        print("[STEP 7] Recording One-Click Playbook Approval...")
        approve_btn = page.locator(".btn-approve-playbook, button:has-text('Approve')").first
        if approve_btn.count() > 0:
            approve_btn.click(force=True)
            page.wait_for_timeout(1000)

            analyst_input = page.locator("#analyst-name-input, input[placeholder*='analyst'], input[type='text']")
            if analyst_input.count() > 0:
                analyst_input.first.fill("analyst_sriram")
                page.wait_for_timeout(500)

            capture_frames(
                duration_sec=3.0,
                phase_title="Step 7: One-Click Playbook Approval & Authorization",
                caption="Digital signature verification authorization for immediate active defense execution.",
                highlight=[450, 200, 1470, 850],
                step_idx=7
            )

            confirm_btn = page.locator(".btn-confirm-approve, button:has-text('Confirm Approval'), button:has-text('Authorize')").first
            if confirm_btn.count() > 0:
                confirm_btn.click(force=True)
                page.wait_for_timeout(1200)

        capture_frames(
            duration_sec=2.5,
            phase_title="Step 7: Playbook State Transition (APPROVED)",
            caption="Playbook transitions to 'APPROVED' with cryptographic audit trail recorded.",
            highlight=[40, 480, 1880, 950],
            step_idx=7
        )

        # -------------------------------------------------------------
        # STEP 8: Multi-Format SOC Export & TAXII 2.1 Threat Sharing
        # -------------------------------------------------------------
        print("[STEP 8] Recording Multi-Format SOC Export & Threat Sharing...")
        capture_frames(
            duration_sec=4.0,
            phase_title="Step 8: Multi-Format SOC Export & TAXII 2.1 Threat Feed",
            caption="Exporting formal STIX 2.1 JSON bundle, executive PDF report, Markdown runbook, and TAXII 2.1 sharing.",
            highlight=[40, 80, 1880, 450],
            step_idx=8
        )

        browser.close()

    print(f"[INFO] Total captured frames: {len(frames)}")

    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos")
    os.makedirs(output_dir, exist_ok=True)

    mp4_path = os.path.join(output_dir, "demo_pipeline_e2e.mp4")
    webp_path = os.path.join(output_dir, "demo_pipeline_e2e.webp")

    # 1. Output MP4 using OpenCV VideoWriter
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(mp4_path, fourcc, fps, (target_width, target_height))
    for frame in frames:
        out.write(frame)
    out.release()
    print(f"[OK] Exported MP4 Demo: {mp4_path} ({os.path.getsize(mp4_path)} bytes)")

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

    print("[SUCCESS] End-to-End Pipeline Demo Recording Complete!")

if __name__ == "__main__":
    record_pipeline_e2e()
