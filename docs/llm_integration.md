# Ollama & Mistral LLM Integration Guide

> **TL;DR** – This guide walks you through setting up Ollama with the Mistral‑7B model (fallback to Gemma‑2B), designing prompt templates, handling time‑outs, and running the LLM in background tasks with graceful degradation.

---

## Table of Contents
1. [Prerequisites](#prerequisites)  
2. [Ollama Installation & Configuration](#ollama-installation--configuration)  
3. [Hardware Requirements](#hardware-requirements)  
4. [Model Selection & Fallback Strategy](#model-selection--fallback-strategy)  
5. [Prompt Architecture](#prompt-architecture)  
6. [Few‑Shot Prompt Engineering](#few-shot-prompt-engineering)  
7. [Response Time Tracking & Timeout Resilience](#response-time-tracking--timeout-resilience)  
8. [Background Task Execution](#background-task-execution)  
9. [Template‑Only Fallback Behavior](#template‑only-fallback-behavior)  
10. [Testing & Validation](#testing--validation)  

---

## 1. Prerequisites
| Item | Minimum version |
|------|-----------------|
| **Python** | 3.10+ |
| **Ollama** | v0.3.5 (or newer) |
| **Git** | 2.30+ |
| **Docker** (optional, for isolated Ollama) | 24.0+ |

> **Note** – The repository already includes `requirements.txt`; ensure you have installed all Python deps (`pip install -r requirements.txt`).

---

## 2. Ollama Installation & Configuration
```bash
# Linux/macOS
curl -fsSL https://ollama.com/install.sh | sh

# Windows (PowerShell)
iwr -useb https://ollama.com/install.ps1 | iex
```

### Start the Ollama daemon
```bash
ollama serve
```
The daemon listens on **`http://localhost:11434`** by default.  If you need a custom port (e.g., when running inside Docker), set the env var:

```bash
export OLLAMA_HOST=0.0.0.0:11434   # Linux/macOS
$env:OLLAMA_HOST="0.0.0.0:11434"   # PowerShell
```

---

## 3. Hardware Requirements
| Scenario | CPU | GPU | RAM | Recommended OS |
|----------|-----|-----|-----|----------------|
| **CPU‑only** | ≥ 8 cores | ✕ | 16 GB | Linux (Ubuntu 22.04) |
| **GPU‑accelerated** | ≥ 4 cores | NVIDIA RTX 3070+ (CUDA 11.8) | 32 GB | Linux (Ubuntu 22.04) |
| **Development VM** | 4 cores | ✕ | 8 GB | Windows 10/11 (WSL2) |

> **Why this matters** – Mistral‑7B (≈7 B parameters) runs comfortably on a single RTX 3070 with ~16 GB VRAM.  The fallback Gemma‑2B can be served on CPU‑only machines.

---

## 4. Model Selection & Fallback Strategy
1. **Primary model** – `mistral:7b` (Ollama model name: `mistral`).  
2. **Fallback model** – `gemma:2b` (Ollama model name: `gemma`).

### Auto‑fallback logic (Python)
```python
import httpx, json, time

OLLAMA_URL = "http://localhost:11434/api/generate"
PRIMARY_MODEL = "mistral"
FALLBACK_MODEL = "gemma"
TIMEOUT_SEC = 8  # per‑request timeout

def generate(prompt: str) -> str:
    payload = {"model": PRIMARY_MODEL, "prompt": prompt}
    try:
        resp = httpx.post(OLLAMA_URL, json=payload, timeout=TIMEOUT_SEC)
        resp.raise_for_status()
        return resp.json()["response"]
    except (httpx.RequestError, httpx.HTTPStatusError):
        # Graceful fallback to the simpler model
        fallback_payload = {"model": FALLBACK_MODEL, "prompt": prompt}
        resp = httpx.post(OLLAMA_URL, json=fallback_payload, timeout=TIMEOUT_SEC)
        resp.raise_for_status()
        return resp.json()["response"]
```
*The fallback is **template‑only** when the request fails – see Section 9.*

---

## 5. Prompt Architecture
We follow a **structured context‑injection** pattern:
```
[SYSTEM] <System‑level directives>
[USER]   <Dynamic context (attack data, indicators, etc.)>
[EXAMPLE] <Few‑shot examples>
[INSTRUCTION] <Task description>
```
### Example skeleton
```text
You are a security analyst assistant. Use the provided indicators and timeline to generate a concise incident narrative.

Context:
{{ attack_summary }}

Examples:
{{ few_shot_examples }}

Instruction:
Summarize the incident in ≤ 300 words, include a severity rating, and list recommended mitigation steps.
```
*All placeholders (`{{ … }}`) are rendered via Jinja2 in `backend/llm/prompts/`.*

---

## 6. Few‑Shot Prompt Engineering
- **Goal:** Provide the model with 1‑3 high‑quality examples that illustrate the desired output style.
- **Technique:** Store examples in `backend/llm/few_shot/` as individual JSON files; load them into the prompt at runtime.

#### Example JSON (`example_01.json`)
```json
{
  "context": "Phishing email targeting finance team, attachment delivered via Office 365.",
  "output": "Incident #1234 – Phishing – High severity – …"
}
```
The rendering code concatenates the examples with a double‑newline separator, preserving formatting.

---

## 7. Response Time Tracking & Timeout Resilience
1. **Timer middleware** (FastAPI) records `latency_ms` for each LLM call and logs it to `metrics.llm_latency`.
2. **Circuit‑breaker** (py‑breaker) opens after **3** consecutive time‑outs, routing all subsequent calls directly to the fallback model for the remainder of the minute.

### Metrics schema (SQLAlchemy)
```python
class LLMMetric(Base):
    __tablename__ = "llm_metrics"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    model = Column(String, index=True)
    latency_ms = Column(Integer)
    success = Column(Boolean)
```

---

## 8. Background Task Execution
LLM calls are dispatched via **FastAPI's `background_tasks`** so the HTTP request returns immediately with a *“Processing…”* token.
```python
@app.post("/api/v1/llm/generate")
async def generate_endpoint(payload: PromptPayload, background: BackgroundTasks):
    task_id = uuid4()
    background.add_task(_run_llm_task, task_id, payload)
    return {"task_id": str(task_id), "status": "queued"}
```
Results are stored in Redis (`redis://localhost:6379/1`) and polled by the front‑end every 2 seconds.

---

## 9. Template‑Only Fallback Behavior
When both the primary and fallback LLM fail (e.g., network outage), the system returns a **static template** that conveys the intent without AI‑generated prose.
```jinja2
# llm_fallback_template.jinja2
Incident Summary (template fallback)
------------------------------------
- **Incident ID:** {{ incident_id }}
- **Detected At:** {{ timestamp }}
- **Description:** Unable to generate AI narrative – please review raw logs.
- **Next Steps:** Manual investigation required.
```
The API response includes `"fallback_mode": "template"` so the UI can display a distinct banner.

---

## 10. Testing & Validation
| Test | Description | Success Criteria |
|------|-------------|------------------|
| **Unit** | `tests/test_llm.py` – mocks `httpx` responses for primary/fallback paths. | 100 % pass |
| **Integration** | End‑to‑end request through `/api/v1/llm/generate`. | Latency < 5 s on GPU, fallback used only when timeout > 8 s |
| **Load** | Run 200 concurrent requests (Locust). | No crashes, circuit‑breaker engages after 3 time‑outs |
| **Documentation** | `docs/llm_integration.md` renders correctly via MkDocs. | No broken links, headings follow hierarchy |

---

## 📌 Quick reference cheat‑sheet
| Item | Command / Code snippet |
|------|------------------------|
| **Start Ollama** | `ollama serve` |
| **Pull Mistral 7B** | `ollama pull mistral` |
| **Pull Gemma 2B** | `ollama pull gemma` |
| **Run LLM (Python)** | `generate(prompt)` (see Section 4) |
| **Check latency metric** | `SELECT * FROM llm_metrics ORDER BY timestamp DESC LIMIT 5;` |
| **Force fallback** | `export OLLAMA_FORCE_FALLBACK=1` |

---

*This document should be version‑controlled alongside the code.  When you merge the PR, the CI pipeline will render the documentation via MkDocs and publish it to the project site.*
