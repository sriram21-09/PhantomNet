import json
import subprocess
import sys

# Configure stdout and stderr to support UTF-8/emojis on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Define target repository details
REPO = "sriram21-09/PhantomNet"

def run_gh_cmd(args):
    """Run a gh CLI command and return the parsed JSON response or output string."""
    cmd = ["gh"] + args
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if res.returncode != 0:
        print(f"Error running command: {' '.join(cmd)}")
        print(f"Stdout: {res.stdout}")
        print(f"Stderr: {res.stderr}")
        return None
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return res.stdout.strip()

def create_or_get_milestone():
    """Create the Month 5 milestone or get its ID/number if it already exists."""
    title = "Month 5 – LLM Integration & Advanced Features (Weeks 17–20)"
    description = "Implementation of local LLM narrative integration, TAXII feed server, MITRE ATT&CK visualization, PDF export, and batch operations."
    due_on = "2026-08-07T23:59:59Z"
    
    # Check existing milestones
    milestones = run_gh_cmd(["api", f"repos/{REPO}/milestones"])
    if isinstance(milestones, list):
        for m in milestones:
            if m.get("title") == title:
                print(f"Milestone '{title}' already exists with number {m.get('number')}")
                return m.get("number")

    # Create milestone
    print(f"Creating milestone '{title}'...")
    res = run_gh_cmd([
        "api", f"repos/{REPO}/milestones",
        "-F", f"title={title}",
        "-F", f"description={description}",
        "-F", f"due_on={due_on}"
    ])
    if res and "number" in res:
        print(f"Milestone created with number {res['number']}")
        return res["number"]
    else:
        print("Failed to create milestone.")
        sys.exit(1)

def create_labels():
    """Create week-17, month-5 and llm-integration labels if they do not exist."""
    labels = [
        {"name": "month-5", "color": "1F6FEB", "description": "Month 5 LLM Integration phase"},
        {"name": "week-17", "color": "0E8A16", "description": "Week 17 tasks"},
        {"name": "llm-integration", "color": "D03AAD", "description": "LLM service and prompts"}
    ]
    for lbl in labels:
        # Check if label exists by trying to create it or fetching it
        print(f"Ensuring label '{lbl['name']}' exists...")
        subprocess.run([
            "gh", "label", "create", lbl["name"],
            "--color", lbl["color"],
            "--description", lbl["description"],
            "--force"
        ])

# Define the 20 daily tasks for Week 17
tasks_definition = [
    # ── Day 1 ──────────────────────────────────────────────────────────────────
    {
        "day": 1,
        "role": "Team Lead",
        "role_label": "team-lead",
        "role_tag": "TeamLead",
        "title": "Design LLM Integration Architecture",
        "objective": "Design the LLM pipeline architecture, define database schema extensions for playbook narratives, and establish communication contracts.",
        "tasks": [
            "- [ ] Draft the Ollama local API communications contract (POST `/api/generate`).",
            "- [ ] Design the prompt template hierarchy and fallback model mechanism.",
            "- [ ] Create database migration plan to add `llm_narrative` column to `sentinel_playbooks` table."
        ],
        "deliverables": [
            "- [ ] Architectural design document outlining the LLM ingestion path and async flow.",
            "- [ ] Database schema migration script/instructions."
        ],
        "estimate": 4
    },
    {
        "day": 1,
        "role": "AI/ML Developer",
        "role_label": "ai-ml-dev",
        "role_tag": "AIMLDeveloper",
        "title": "Research and Document Ollama Installation Steps",
        "objective": "Research dockerized Ollama installation, pull the target Mistral 7B model, and document containerized setup steps.",
        "tasks": [
            "- [ ] Research and test Docker container installation procedures for Ollama server with GPU pass-through.",
            "- [ ] Pull the `mistral` model inside the docker container and benchmark initialization and basic inference speed.",
            "- [ ] Write a developer bootstrap document detailing system pre-requisites and Docker Compose setup steps."
        ],
        "deliverables": [
            "- [ ] Local developer installation guide (`docs/ollama_docker_setup.md`).",
            "- [ ] Basic benchmark statistics (latency per token, load times)."
        ],
        "estimate": 4
    },
    {
        "day": 1,
        "role": "Security Developer",
        "role_label": "security-dev",
        "role_tag": "SecurityDeveloper",
        "title": "Create backend/sentinel/llm_service.py Scaffold",
        "objective": "Scaffold the main LLM Service module to encapsulate Ollama interactions and state toggles.",
        "tasks": [
            "- [ ] Create the `backend/sentinel/llm_service.py` module file.",
            "- [ ] Define the `LLMService` class with a stub for `generate_narrative(context_data) -> str`.",
            "- [ ] Bind execution controls to the `SENTINEL_LLM_ENABLED` and `SENTINEL_LLM_HOST` environment variables."
        ],
        "deliverables": [
            "- [ ] Scaffolded `llm_service.py` file with basic class and configuration validation."
        ],
        "estimate": 4
    },
    {
        "day": 1,
        "role": "Frontend Developer",
        "role_label": "frontend-dev",
        "role_tag": "FrontendDeveloper",
        "title": "Add LLM Status Indicator to Dashboard",
        "objective": "Integrate an AI service status indicator in the Sentinel dashboard UI.",
        "tasks": [
            "- [ ] Design a status badge in the dashboard header showing AI online/offline state.",
            "- [ ] Wire the badge to fetch status from the frontend state manager.",
            "- [ ] Create simple mock states to test status styling."
        ],
        "deliverables": [
            "- [ ] Visual badge showing \"AI: Online\" (green) or \"AI: Offline\" (gray) on the frontend dashboard."
        ],
        "estimate": 4
    },
    # ── Day 2 ──────────────────────────────────────────────────────────────────
    {
        "day": 2,
        "role": "Team Lead",
        "role_label": "team-lead",
        "role_tag": "TeamLead",
        "title": "Create LLM Status Endpoint /api/sentinel/llm/status",
        "objective": "Implement a backend endpoint to expose LLM configuration and health status.",
        "tasks": [
            "- [ ] Add the `/api/sentinel/llm/status` endpoint in the FastAPI backend.",
            "- [ ] Return details such as enabled/disabled state, model name, and host connection status.",
            "- [ ] Implement health check checks that verify if the dockerized Ollama daemon (`SENTINEL_LLM_HOST`) is reachable."
        ],
        "deliverables": [
            "- [ ] `/api/sentinel/llm/status` API endpoint with JSON response and health check logic."
        ],
        "estimate": 4
    },
    {
        "day": 2,
        "role": "AI/ML Developer",
        "role_label": "ai-ml-dev",
        "role_tag": "AIMLDeveloper",
        "title": "Install Ollama and Mistral 7B on Development Machines",
        "objective": "Configure the local developer environment with a working dockerized Ollama container and Mistral 7B model.",
        "tasks": [
            "- [ ] Start the `ollama` container (`docker compose up -d ollama`) and confirm it starts correctly on port 11434.",
            "- [ ] Run `docker exec -it phantomnet_ollama ollama pull mistral` and verify model availability inside the container.",
            "- [ ] Document alternative/smaller fallback models (e.g., `phi3:3.8b` or `gemma:2b`) for resource-constrained systems."
        ],
        "deliverables": [
            "- [ ] Verified local installation of Ollama running on port 11434.",
            "- [ ] Successfully verified API query to `/api/generate` using curl."
        ],
        "estimate": 4
    },
    {
        "day": 2,
        "role": "Security Developer",
        "role_label": "security-dev",
        "role_tag": "SecurityDeveloper",
        "title": "Build LLM Prompt Template for Playbooks",
        "objective": "Create structured prompt templates that safely inject security incident context for narrative summaries.",
        "tasks": [
            "- [ ] Design the markdown-oriented prompt structure inside the backend templates.",
            "- [ ] Include structured sections: Campaign Cluster Metadata, Source IPs/IOCs, MITRE ATT&CK Mapping, and Mitigation Steps.",
            "- [ ] Ensure UTC timestamp standardization across prompt inputs."
        ],
        "deliverables": [
            "- [ ] Prompt template files or module constants containing instructions for the local LLM."
        ],
        "estimate": 4
    },
    {
        "day": 2,
        "role": "Frontend Developer",
        "role_label": "frontend-dev",
        "role_tag": "FrontendDeveloper",
        "title": "Add AI Summary Section to PlaybookViewer",
        "objective": "Integrate an expandable section in the Playbook modal to display the AI summary.",
        "tasks": [
            "- [ ] Create an \"AI Summary\" section inside the PlaybookViewer modal.",
            "- [ ] Add toggle buttons to expand or collapse the summary.",
            "- [ ] Setup mock loading states and placeholder cards."
        ],
        "deliverables": [
            "- [ ] Modal UI updates in PlaybookViewer with the new summary section and accordion toggles."
        ],
        "estimate": 4
    },
    # ── Day 3 ──────────────────────────────────────────────────────────────────
    {
        "day": 3,
        "role": "Team Lead",
        "role_label": "team-lead",
        "role_tag": "TeamLead",
        "title": "Add LLM Toggle to SystemConfig API",
        "objective": "Integrate the LLM status flag into the global SystemConfig model and admin control endpoints.",
        "tasks": [
            "- [ ] Add `sentinel_llm_enabled` boolean flag to the SystemConfig database model.",
            "- [ ] Update administrative endpoints to allow dynamic updates of this configuration.",
            "- [ ] Verify that system settings reflect dynamic toggle adjustments in real-time."
        ],
        "deliverables": [
            "- [ ] Database schema modification for SystemConfig.",
            "- [ ] Config endpoints supporting dynamic updates of the LLM enable/disable flag."
        ],
        "estimate": 4
    },
    {
        "day": 3,
        "role": "AI/ML Developer",
        "role_label": "ai-ml-dev",
        "role_tag": "AIMLDeveloper",
        "title": "Verify and Test LLM Output Quality for SSH Campaign",
        "objective": "Analyze the quality, reliability, and security compliance of AI-generated summaries for SSH Brute Force attacks.",
        "tasks": [
            "- [ ] Run raw prompts containing SSH brute force telemetry against local Mistral.",
            "- [ ] Evaluate response structure, formatting, and markdown layout correctness.",
            "- [ ] Adjust prompt phrasing to eliminate hallucinations and enforce formatting boundaries."
        ],
        "deliverables": [
            "- [ ] Quality evaluation report detailing prompt, raw output, and response quality adjustments."
        ],
        "estimate": 4
    },
    {
        "day": 3,
        "role": "Security Developer",
        "role_label": "security-dev",
        "role_tag": "SecurityDeveloper",
        "title": "Implement Async Ollama HTTP Client in llm_service.py",
        "objective": "Build an asynchronous HTTP client to communicate with the dockerized Ollama API via the internal network without blocking the application.",
        "tasks": [
            "- [ ] Integrate `httpx.AsyncClient` inside `llm_service.py` to target the dynamic `SENTINEL_LLM_HOST` endpoint.",
            "- [ ] Configure a strict 60-second connection and read timeout.",
            "- [ ] Ensure response streaming or aggregation is parsed correctly into clean markdown text."
        ],
        "deliverables": [
            "- [ ] Completed asynchronous HTTP connection logic inside `LLMService`."
        ],
        "estimate": 4
    },
    {
        "day": 3,
        "role": "Frontend Developer",
        "role_label": "frontend-dev",
        "role_tag": "FrontendDeveloper",
        "title": "Style AI-Enhanced Summary Narrative on Frontend",
        "objective": "Apply custom styling to make the AI narrative visually distinct from standard template text.",
        "tasks": [
            "- [ ] Design custom borders, glow effects, or icons for the AI summary card.",
            "- [ ] Add an \"AI-Enhanced Narrative\" badge to clearly designate it as model output.",
            "- [ ] Support dark mode and responsive layout variations."
        ],
        "deliverables": [
            "- [ ] Fully styled React components for the AI Summary card with premium borders and badges."
        ],
        "estimate": 4
    },
    # ── Day 4 ──────────────────────────────────────────────────────────────────
    {
        "day": 4,
        "role": "Team Lead",
        "role_label": "team-lead",
        "role_tag": "TeamLead",
        "title": "Integrate llm_service Asynchronously into Sentinel Service Orchestrator",
        "objective": "Connect the LLM generation task into the main playbook generation pipeline using asynchronous background tasks.",
        "tasks": [
            "- [ ] Modify `SentinelService.generate_playbook` to call the LLM service when enabled.",
            "- [ ] Wrap the LLM call in FastAPI `BackgroundTasks` to prevent database write connection locks.",
            "- [ ] Persist the generated markdown summary to the new `llm_narrative` column in `SentinelPlaybook`."
        ],
        "deliverables": [
            "- [ ] Refactored `SentinelService` orchestrator with asynchronous background LLM processing."
        ],
        "estimate": 4
    },
    {
        "day": 4,
        "role": "AI/ML Developer",
        "role_label": "ai-ml-dev",
        "role_tag": "AIMLDeveloper",
        "title": "Verify and Test LLM Output for SQLi and Port Scan Campaigns",
        "objective": "Verify LLM quality, formatting, and correctness for SQL Injection and Port Scanning campaigns.",
        "tasks": [
            "- [ ] Test prompt output formatting using mock SQLi and Port Scan telemetry.",
            "- [ ] Refine prompts to ensure precise mapping of technical indicators.",
            "- [ ] Document generation latency for each campaign type."
        ],
        "deliverables": [
            "- [ ] Test logs containing prompt inputs and generated outputs for SQLi and Port Scan scenarios."
        ],
        "estimate": 4
    },
    {
        "day": 4,
        "role": "Security Developer",
        "role_label": "security-dev",
        "role_tag": "SecurityDeveloper",
        "title": "Build Robust Fallback/Mock Mechanisms for Offline LLM",
        "objective": "Ensure system stability by creating fallback strategies when the Ollama server is offline or fails.",
        "tasks": [
            "- [ ] Catch network timeouts, connection errors, and status failures inside `llm_service.py`.",
            "- [ ] Implement a fallback to template-only generation with logged warnings (no crashes).",
            "- [ ] Support a mock client configuration option in the service for testing."
        ],
        "deliverables": [
            "- [ ] Fallback logic implementation with connection validation.",
            "- [ ] Mock generator output functionality for test execution."
        ],
        "estimate": 4
    },
    {
        "day": 4,
        "role": "Frontend Developer",
        "role_label": "frontend-dev",
        "role_tag": "FrontendDeveloper",
        "title": "Add Regenerate AI Summary Button in PlaybookViewer",
        "objective": "Provide admins and analysts the ability to manually trigger AI summary regeneration from the UI.",
        "tasks": [
            "- [ ] Add a 'Regenerate AI Summary' button to the PlaybookViewer modal.",
            "- [ ] Add loading animations and disable states during active regeneration requests.",
            "- [ ] Connect the button to trigger the backend regeneration endpoint."
        ],
        "deliverables": [
            "- [ ] PlaybookViewer UI with fully functional regeneration button and state management."
        ],
        "estimate": 4
    },
    # ── Day 5 ──────────────────────────────────────────────────────────────────
    {
        "day": 5,
        "role": "Team Lead",
        "role_label": "team-lead",
        "role_tag": "TeamLead",
        "title": "Write Integration Tests for llm_service.py",
        "objective": "Develop a comprehensive integration test suite for the LLM service.",
        "tasks": [
            "- [ ] Create `tests/test_llm_service.py` to cover `LLMService` functionality.",
            "- [ ] Test toggle behavior (enabled/disabled states) and timeout exception handling.",
            "- [ ] Test the graceful fallback mechanism when the Ollama API throws an error."
        ],
        "deliverables": [
            "- [ ] Integration test file `tests/test_llm_service.py` with mock response testing."
        ],
        "estimate": 4
    },
    {
        "day": 5,
        "role": "AI/ML Developer",
        "role_label": "ai-ml-dev",
        "role_tag": "AIMLDeveloper",
        "title": "Fine-tune LLM Prompt Template Based on Output Testing",
        "objective": "Apply final refinements and few-shot examples to the prompt templates to lock down performance.",
        "tasks": [
            "- [ ] Review outputs collected during the week and identify formatting edge-cases.",
            "- [ ] Embed few-shot examples to reinforce output constraints and Markdown formatting.",
            "- [ ] Confirm that outputs fit cleanly inside the frontend markdown renderer."
        ],
        "deliverables": [
            "- [ ] Final locked prompt templates configured in the system."
        ],
        "estimate": 4
    },
    {
        "day": 5,
        "role": "Security Developer",
        "role_label": "security-dev",
        "role_tag": "SecurityDeveloper",
        "title": "Track and Log LLM API Performance and Latency",
        "objective": "Integrate logging mechanisms to trace LLM request duration and resource load.",
        "tasks": [
            "- [ ] Add response time tracking to the generation logic inside `llm_service.py`.",
            "- [ ] Log latency metrics and include them in the `/api/sentinel/llm/status` response data.",
            "- [ ] Set up warnings for slow inference requests exceeding 25 seconds."
        ],
        "deliverables": [
            "- [ ] Timing logic code changes and API metric tracking integration."
        ],
        "estimate": 4
    },
    {
        "day": 5,
        "role": "Frontend Developer",
        "role_label": "frontend-dev",
        "role_tag": "FrontendDeveloper",
        "title": "Conduct Full E2E Pipeline Verification with LLM Enabled",
        "objective": "Perform full end-to-end user path testing to verify active LLM playbook enrichment.",
        "tasks": [
            "- [ ] Simulate a threat campaign (e.g. SSH brute force) in the Docker Compose environment and trigger playbook creation.",
            "- [ ] Verify that the backend container runs the background task, queries the ollama container, and updates the database.",
            "- [ ] Open the dashboard and check the playbook modal for correct rendering of the AI narrative."
        ],
        "deliverables": [
            "- [ ] E2E validation report or video demonstrating active AI-enriched playbooks."
        ],
        "estimate": 4
    }
]

MILESTONE_TITLE = "Month 5 – LLM Integration & Advanced Features (Weeks 17–20)"

def create_issues(milestone_title):
    """Loop through the tasks and create them on GitHub."""
    for idx, t in enumerate(tasks_definition):
        title = f"Week 17-Day {t['day']},{t['role']},{t['title']}"
        print(f"Creating Issue {idx+1}/20: {title}...")
        
        # Build Body
        body = f"""## 🎯 Objective
{t['objective']}

## 🛠️ Tasks
{chr(10).join(t['tasks'])}

## 📦 Deliverables
{chr(10).join(t['deliverables'])}

## ⏱️ Estimate
{t['estimate']} hours

---
#PhantomNet #Week17 #{t['role_tag']}
"""
        # Define command and args
        # Labels are month-5, week-17, llm-integration, and the role label
        labels_str = f"month-5,week-17,llm-integration,{t['role_label']}"
        
        cmd = [
            "issue", "create",
            "--title", title,
            "--body", body,
            "--milestone", milestone_title,
            "--label", labels_str,
            "--assignee", "sriram21-09"
        ]
        
        res = run_gh_cmd(cmd)
        if res:
            print(f"  Successfully created issue: {res}")
        else:
            print("  Failed to create issue.")

def main():
    # 1. Milestone
    create_or_get_milestone()
    
    # 2. Labels
    create_labels()
    
    # 3. Create all issues
    create_issues(MILESTONE_TITLE)
    
    print("\nAll tasks completed successfully!")

if __name__ == "__main__":
    main()
