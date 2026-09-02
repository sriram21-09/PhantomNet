# Demo #3: AI Narrative Generation & MITRE ATT&CK Heatmap

## Objective
Create a concise, high‑impact demo video showcasing:
1. **LLM Narrative Generation** – Real‑time generation using Ollama with Mistral model, with graceful fallback to a static template when the LLM service is unavailable.
2. **Interactive MITRE ATT&CK Matrix** – Visual heatmap of technique coverage, with filtering by tactic, severity, and time window.
3. **Quality Scoring** – Dynamic scoring of generated playbooks (0‑100) displayed on the dashboard.
4. **Campaign Timeline Progression** – Live chart showing attack events over time as they are ingested.

## Technical Setup
- **Frontend**: React + Vite (`http://localhost:5173/sentinel`). Use the existing dark cyber‑security theme.
- **Backend**: FastAPI (`http://127.0.0.1:8000`). Ensure the LLM service (Ollama) is running with the `mistral` model.
- **Viewport**: 1920×1080 (Full HD) for 1080p video.
- **Recording Tool**: Use OBS Studio (or any screen‑capture utility) to record the full workflow.

## Recording Steps
1. **Start Services**
   ```bash
   # In separate terminals
   cd backend && uvicorn sentinel:app --reload
   cd frontend-dev && npm run dev
   ollama serve &
   ollama run mistral
   ```
2. **Navigate to Sentinel UI** – Open `http://localhost:5173/sentinel` in Chrome.
3. **Phase 1 – Simulate Attack**
   - Trigger a simulated SSH brute‑force attempt (`T1110.001`).
   - Verify the event appears in the *Topology* view.
4. **Phase 2 – LLM Narrative Generation**
   - Click **Generate Narrative**. Record the UI showing the LLM‑generated paragraph.
   - Stop the Ollama container, click again, and capture the fallback static template.
5. **Phase 3 – MITRE ATT&CK Heatmap**
   - Open the **ATT&CK Matrix** tab.
   - Apply filters (e.g., *Credential Access*, *Severity > 80*). Record the heatmap updating.
6. **Phase 4 – Quality Scoring**
   - Observe the **Score** badge on the generated playbook (e.g., `92/100`).
7. **Phase 5 – Campaign Timeline**
   - Switch to the **Timeline** view. Show the line‑chart growing as events stream in.
8. **Export** – Export the playbook as PDF and STIX bundle, capture the download dialogs.
9. **Wrap‑up** – Stop the recording, trim to ~3 minutes.

## Post‑Processing
- Encode the recording to `demos/demo_ai_mitre.mp4` (H.264, 1080p, ~5 Mbps).
- Generate a WebP preview `demos/demo_ai_mitre.webp` for quick GitHub preview.

## Checklist
- [ ] Ollama + Mistral running
- [ ] Frontend & backend reachable
- [ ] OBS capture settings: 1920×1080, 30 fps
- [ ] Video trimmed to < 4 min
- [ ] Files placed in `demos/` directory

---
*This script is intended for developers to reproduce the demo recording consistently.*
