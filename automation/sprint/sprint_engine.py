"""
PhantomNet Sprint Automation Engine v4.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
One-shot automation: creates milestone, labels, Day field options,
GitHub issues, adds to Project Board, syncs all custom fields,
and appends critical warnings — all from a single JSON data file.

USAGE:
  python automation/sprint/sprint_engine.py --config automation/sprint/week14_config.json

PREREQUISITES:
  1. gh CLI authenticated (gh auth status)
  2. A valid week config JSON file (see CONFIG FORMAT below)

WHAT IT DOES (in order):
  Phase 1: Pre-flight validation (gh CLI, repo access)
  Phase 2: Ensure milestone exists (create if missing)
  Phase 3: Ensure labels exist (create if missing)
  Phase 4: Ensure Day field options exist (add if missing)
  Phase 5: Create issues (skip duplicates)
  Phase 6: Assign milestone to all issues
  Phase 7: Add issues to Project Board + sync Role/Type/Day fields
"""

import subprocess
import json
import sys
import time
import argparse
from pathlib import Path

# ━━━━━━━━━━━━━━━━━━━━━ CONFIGURATION ━━━━━━━━━━━━━━━━━━━━━
PROJECT_NUMBER = "5"
PROJECT_OWNER = "sriram21-09"
PROJECT_ID = "PVT_kwHOCn3zZM4BKFg8"
REPO = "sriram21-09/PhantomNet"

FIELD_IDS = {
    "Day":  "PVTSSF_lAHOCn3zZM4BKFg8zg6cR2A",
    "Role": "PVTSSF_lAHOCn3zZM4BKFg8zg6cR9I",
    "Type": "PVTSSF_lAHOCn3zZM4BKFg8zg6cSJQ",
}

ROLE_OPTIONS = {
    "Team Lead":          "3614ec82",
    "Security Developer": "9ba5b34a",
    "AI/ML Developer":    "32be766c",
    "Frontend Developer": "cd819157",
    "All":                "6559ba2b",
}

TYPE_OPTIONS = {
    "Feature":       "75837f34",
    "Integration":   "f456660c",
    "Testing":       "8e98cc09",
    "Documentation": "6949cc86",
    "Review":        "263bba77",
}

LABEL_MAP = {
    "Team Lead":          "team-lead",
    "AI/ML Developer":    "ai-ml-dev",
    "Security Developer": "security-dev",
    "Frontend Developer": "frontend-dev",
    "All":                "team-lead",
}

ASSIGNEE_MAP = {
    "Team Lead":          "sriram21-09",
    "Security Developer": "VivekanandaReddy2006",
    "AI/ML Developer":    "vikranthN101",
    "Frontend Developer": "sairammanideepreddy2123",
}

# ━━━━━━━━━━━━━━━━━━━━━ HELPERS ━━━━━━━━━━━━━━━━━━━━━━━━━━━
def run_gh(args):
    """Run gh CLI command, return stdout or None on failure."""
    try:
        res = subprocess.run(
            ["gh"] + args,
            capture_output=True, text=False, check=False
        )
        if res.returncode != 0:
            return None
        return res.stdout.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None


def run_gh_verbose(args):
    """Run gh CLI command, return (stdout, stderr) tuple."""
    try:
        res = subprocess.run(
            ["gh"] + args,
            capture_output=True, text=False, check=False
        )
        stdout = res.stdout.decode("utf-8", errors="ignore").strip() if res.stdout else ""
        stderr = res.stderr.decode("utf-8", errors="ignore").strip() if res.stderr else ""
        return stdout if res.returncode == 0 else None, stderr
    except Exception as e:
        return None, str(e)


def set_field(item_id, field_id, option_id):
    """Set a single-select field on a project item."""
    res = subprocess.run([
        "gh", "project", "item-edit",
        "--id", item_id,
        "--project-id", PROJECT_ID,
        "--field-id", field_id,
        "--single-select-option-id", option_id
    ], capture_output=True, text=False)
    return res.returncode == 0


# ━━━━━━━━━━━━━━━━ PHASE 1: VALIDATION ━━━━━━━━━━━━━━━━━━━
def phase1_validate(config):
    print("\n" + "=" * 60)
    print("  PHASE 1: Pre-Flight Validation")
    print("=" * 60)

    ver = run_gh(["--version"])
    if not ver:
        print("  [FAIL] gh CLI not found.")
        sys.exit(1)
    print(f"  [OK] gh CLI: {ver.splitlines()[0]}")

    auth = run_gh(["auth", "status"])
    if auth is None:
        print("  [WARN] gh auth status returned error — may still work")
    else:
        print("  [OK] Authenticated")

    tasks = config.get("tasks", [])
    week = config["week"]
    print(f"  [OK] Week: {week}")
    print(f"  [OK] Tasks: {len(tasks)}")
    print(f"  [OK] Milestone: {config.get('milestone_title', 'N/A')}")
    print(f"  [OK] Days: {list(config.get('day_map', {}).values())}")

    # Validate each task
    required = ["Day", "Role", "Assignee", "Title", "Objective", "Tasks", "Deliverables", "Estimate", "Type"]
    errors = 0
    for i, t in enumerate(tasks):
        for field in required:
            if field not in t:
                print(f"  [ERR] Task {i+1} missing '{field}'")
                errors += 1
    if errors:
        print(f"\n  [FAIL] {errors} validation errors. Fix config and retry.")
        sys.exit(1)
    print(f"  [OK] All tasks validated")


# ━━━━━━━━━━━━━━ PHASE 2: MILESTONE ━━━━━━━━━━━━━━━━━━━━━━
def phase2_milestone(config):
    print("\n" + "=" * 60)
    print("  PHASE 2: Ensure Milestone Exists")
    print("=" * 60)

    title = config.get("milestone_title", "")
    desc = config.get("milestone_description", "")
    if not title:
        print("  [SKIP] No milestone specified")
        return

    # Check if exists
    raw = run_gh(["api", f"repos/{REPO}/milestones?state=all",
                  "--jq", f'[.[] | select(.title == "{title}")] | length'])
    if raw and int(raw) > 0:
        print(f"  [OK] Milestone already exists: {title}")
        return

    # Create
    result = run_gh(["api", f"repos/{REPO}/milestones", "--method", "POST",
                     "--field", f"title={title}",
                     "--field", f"description={desc}",
                     "--field", "state=open"])
    if result:
        print(f"  [OK] Created milestone: {title}")
    else:
        print(f"  [WARN] Could not create milestone (may need manual creation)")


# ━━━━━━━━━━━━━━ PHASE 3: LABELS ━━━━━━━━━━━━━━━━━━━━━━━━━
def phase3_labels(config):
    print("\n" + "=" * 60)
    print("  PHASE 3: Ensure Labels Exist")
    print("=" * 60)

    labels_to_create = config.get("labels", [])
    if not labels_to_create:
        print("  [SKIP] No labels to create")
        return

    # Get existing labels
    raw = run_gh(["label", "list", "--repo", REPO, "--json", "name", "--limit", "200"])
    existing = {l["name"] for l in json.loads(raw)} if raw else set()

    for label in labels_to_create:
        name = label["name"]
        if name in existing:
            print(f"  [OK] Already exists: {name}")
            continue
        result, err = run_gh_verbose([
            "label", "create", name,
            "--repo", REPO,
            "--description", label.get("description", ""),
            "--color", label.get("color", "1D76DB")
        ])
        if result is not None:
            print(f"  [OK] Created: {name}")
        else:
            print(f"  [WARN] Could not create {name}: {err[:60]}")
        time.sleep(0.2)


# ━━━━━━━━━━━━━━ PHASE 4: DAY FIELD OPTIONS ━━━━━━━━━━━━━━
def phase4_day_options(config):
    print("\n" + "=" * 60)
    print("  PHASE 4: Ensure Day Field Options Exist")
    print("=" * 60)

    day_map = config.get("day_map", {})
    if not day_map:
        print("  [SKIP] No day_map in config")
        return

    new_day_names = set(day_map.values())

    # Get existing options
    raw = run_gh(["project", "field-list", PROJECT_NUMBER,
                  "--owner", PROJECT_OWNER, "--format", "json"])
    if not raw:
        print("  [FAIL] Could not load project fields")
        return

    fields = json.loads(raw)
    day_field = next((f for f in fields["fields"] if f["id"] == FIELD_IDS["Day"]), None)
    if not day_field:
        print("  [FAIL] Day field not found on project board")
        return

    existing_opts = day_field.get("options", [])
    existing_names = {o["name"] for o in existing_opts}
    to_add = [n for n in new_day_names if n not in existing_names]

    if not to_add:
        print(f"  [OK] All {len(new_day_names)} Day options already exist")
        # Store option IDs for later use
        config["_day_option_ids"] = {o["name"]: o["id"] for o in existing_opts if o["name"] in new_day_names}
        return

    # Build mutation to add new options while preserving existing
    all_options = []
    for opt in existing_opts:
        all_options.append(f'{{id: "{opt["id"]}", name: "{opt["name"]}", color: BLUE, description: ""}}')
    for name in to_add:
        week = config["week"]
        all_options.append(f'{{name: "{name}", color: GREEN, description: "Week {week}"}}')

    options_str = "[" + ", ".join(all_options) + "]"
    query = (
        'mutation { updateProjectV2Field(input: { '
        f'fieldId: "{FIELD_IDS["Day"]}" '
        f'singleSelectOptions: {options_str}'
        ' }) { projectV2Field { ... on ProjectV2SingleSelectField { id options { id name } } } } }'
    )

    result = run_gh(["api", "graphql", "-f", f"query={query}"])
    if result:
        data = json.loads(result)
        errs = data.get("errors")
        if errs:
            print(f"  [FAIL] GraphQL errors: {json.dumps(errs[:2])[:200]}")
        else:
            new_opts = data.get("data", {}).get("updateProjectV2Field", {}).get("projectV2Field", {}).get("options", [])
            config["_day_option_ids"] = {o["name"]: o["id"] for o in new_opts if o["name"] in new_day_names}
            print(f"  [OK] Day field now has {len(new_opts)} options")
            for name in to_add:
                oid = config["_day_option_ids"].get(name, "?")
                print(f"    NEW: {name} -> {oid}")
    else:
        print("  [FAIL] GraphQL mutation failed")


# ━━━━━━━━━━━━━━ PHASE 5: ISSUE CREATION ━━━━━━━━━━━━━━━━━
def phase5_create_issues(config):
    print("\n" + "=" * 60)
    print("  PHASE 5: Create Issues")
    print("=" * 60)

    week = config["week"]
    milestone = config.get("milestone_title", "")
    week_label = f"week-{week}"
    month_label = config.get("month_label", "")
    extra_labels = config.get("extra_labels", [])
    created = 0
    skipped = 0

    for task in config["tasks"]:
        title = f"Week {week}-Day {task['Day']},{task['Role']},{task['Title']}"

        # Check duplicate
        existing = run_gh(["issue", "list", "--search", f'"{title}"',
                           "--state", "all", "--json", "url", "--jq", ".[0].url"])
        if existing and existing.startswith("http"):
            print(f"  [SKIP] {title[:70]}")
            skipped += 1
            continue

        # Build body
        tasks_str = "".join([f"- [ ] {t}\n" for t in task["Tasks"]])
        deliv_str = "".join([f"- [ ] {d}\n" for d in task["Deliverables"]])

        body = f"""## \U0001f3af Objective
{task['Objective']}

## \U0001f6e0\ufe0f Tasks
{tasks_str}
## \U0001f4e6 Deliverables
{deliv_str}
## \u23f1\ufe0f Estimate
{task['Estimate']} hours

---
#PhantomNet #Week{week} #{task['Role']}
"""

        # Append critical warnings if specified
        if task.get("Warnings"):
            body += "\n---\n\n## \u26a0\ufe0f Critical Implementation Warnings\n\n"
            for warning in task["Warnings"]:
                body += f"> {warning}\n\n"

        # Build command
        role_label = LABEL_MAP.get(task["Role"], "planning")
        cmd = [
            "issue", "create",
            "--title", title,
            "--body", body,
            "--label", role_label,
            "--label", week_label,
            "--assignee", task["Assignee"],
        ]
        if month_label:
            cmd += ["--label", month_label]
        for lbl in extra_labels:
            cmd += ["--label", lbl]
        if milestone:
            cmd += ["--milestone", milestone]

        url = run_gh(cmd)
        if url:
            print(f"  [OK] #{url.split('/')[-1]} {title[:65]}")
            created += 1
        else:
            # Retry without milestone (encoding issues)
            cmd_no_ms = [c for c in cmd if c != "--milestone" and c != milestone]
            url = run_gh(cmd_no_ms)
            if url:
                print(f"  [OK] #{url.split('/')[-1]} {title[:65]} (no milestone)")
                created += 1
            else:
                print(f"  [FAIL] {title[:65]}")

        time.sleep(0.5)

    print(f"\n  Created: {created} | Skipped: {skipped} | Total: {created + skipped}")


# ━━━━━━━━━━━ PHASE 6: MILESTONE ASSIGNMENT ━━━━━━━━━━━━━━
def phase6_assign_milestone(config):
    print("\n" + "=" * 60)
    print("  PHASE 6: Assign Milestone to All Issues")
    print("=" * 60)

    milestone = config.get("milestone_title", "")
    if not milestone:
        print("  [SKIP] No milestone")
        return

    week = config["week"]
    week_label = f"week-{week}"

    raw = run_gh(["issue", "list", "--repo", REPO, "--state", "all",
                  "--label", week_label, "--json", "number,milestone", "--limit", "30"])
    if not raw:
        print("  [FAIL] Could not list issues")
        return

    issues = json.loads(raw)

    # Get milestone number
    ms_raw = run_gh(["api", f"repos/{REPO}/milestones?state=all",
                     "--jq", f'.[] | select(.title == "{milestone}") | .number'])
    if not ms_raw:
        # Try with partial match
        ms_raw = run_gh(["api", f"repos/{REPO}/milestones?state=all",
                         "--jq", ".[].number"])

    ms_number = ms_raw.splitlines()[0] if ms_raw else None

    assigned = 0
    for issue in issues:
        if issue.get("milestone"):
            continue
        if ms_number:
            result = run_gh(["issue", "edit", str(issue["number"]),
                             "--repo", REPO, "--milestone", ms_number])
            if result is not None:
                assigned += 1
            time.sleep(0.2)

    print(f"  [OK] {assigned} issues newly assigned | {len(issues) - assigned} already had milestone")


# ━━━━━━━━━━ PHASE 7: PROJECT BOARD SYNC ━━━━━━━━━━━━━━━━━
def phase7_sync_project(config):
    print("\n" + "=" * 60)
    print("  PHASE 7: Project Board Sync (Add + Set Fields)")
    print("=" * 60)

    week = config["week"]
    week_label = f"week-{week}"
    day_map = config.get("day_map", {})

    # Get day option IDs (may have been cached in phase 4)
    day_option_ids = config.get("_day_option_ids", {})
    if not day_option_ids and day_map:
        # Fetch fresh
        raw = run_gh(["project", "field-list", PROJECT_NUMBER,
                      "--owner", PROJECT_OWNER, "--format", "json"])
        if raw:
            fields = json.loads(raw)
            day_field = next((f for f in fields["fields"] if f["id"] == FIELD_IDS["Day"]), None)
            if day_field:
                day_option_ids = {o["name"]: o["id"] for o in day_field.get("options", [])}

    # Get all issues for this week
    raw = run_gh(["issue", "list", "--repo", REPO, "--state", "all",
                  "--label", week_label, "--json", "number,title", "--limit", "30"])
    if not raw:
        print("  [FAIL] Could not list issues")
        return
    issues = json.loads(raw)
    print(f"  Found {len(issues)} issues")

    # Get current project items
    items_raw = run_gh(["project", "item-list", PROJECT_NUMBER,
                        "--owner", PROJECT_OWNER, "--format", "json", "--limit", "400"])
    issue_to_item = {}
    if items_raw:
        items_data = json.loads(items_raw)
        for item in items_data.get("items", []):
            content = item.get("content", {})
            if content.get("type") == "Issue":
                issue_to_item[content.get("number")] = item["id"]

    # Build task lookup from config
    task_lookup = {}
    for task in config["tasks"]:
        key = task["Title"][:25].lower()
        task_lookup[key] = task

    synced = 0
    for issue in sorted(issues, key=lambda x: x["number"]):
        num = issue["number"]
        title = issue["title"]

        # Parse title: "Week X-Day Y,Role,Title"
        parts = title.split(",", 2)
        if len(parts) < 3:
            print(f"  [SKIP] #{num} — can't parse title")
            continue

        role = parts[1].strip()
        task_title = parts[2].strip()

        # Extract day number
        day_num = None
        for d in range(1, 8):
            if f"Day {d}" in parts[0]:
                day_num = d
                break

        # Find matching task type from config
        task_type = "Feature"
        for task in config["tasks"]:
            if task["Title"][:20] in task_title[:25] or task_title[:20] in task["Title"][:25]:
                task_type = task.get("Type", "Feature")
                break

        # Get or create project item
        item_id = issue_to_item.get(num)
        if not item_id:
            url = f"https://github.com/{REPO}/issues/{num}"
            add_res = run_gh(["project", "item-add", PROJECT_NUMBER,
                              "--owner", PROJECT_OWNER,
                              "--url", url, "--format", "json"])
            if add_res:
                item_id = json.loads(add_res).get("id")
            else:
                print(f"  [FAIL] #{num} — could not add to project")
                continue
            time.sleep(0.3)

        # Set Role
        role_oid = ROLE_OPTIONS.get(role)
        if role_oid:
            set_field(item_id, FIELD_IDS["Role"], role_oid)

        # Set Type
        type_oid = TYPE_OPTIONS.get(task_type)
        if type_oid:
            set_field(item_id, FIELD_IDS["Type"], type_oid)

        # Set Day
        if day_num:
            day_name = day_map.get(str(day_num))
            if day_name:
                day_oid = day_option_ids.get(day_name)
                if day_oid:
                    set_field(item_id, FIELD_IDS["Day"], day_oid)
                else:
                    print(f"    [WARN] Day option '{day_name}' not found")

        synced += 1
        print(f"  [OK] #{num} | {role} | Day {day_num} | {task_type}")
        time.sleep(0.3)

    print(f"\n  Synced: {synced}/{len(issues)}")


# ━━━━━━━━━━━━━━━━━━━━━ MAIN ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    parser = argparse.ArgumentParser(
        description="PhantomNet Sprint Automation Engine v4.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLE:
  python automation/sprint/sprint_engine.py --config automation/sprint/week14_config.json
  python automation/sprint/sprint_engine.py --config automation/sprint/week14_config.json --skip-create
        """
    )
    parser.add_argument("--config", required=True, help="Path to week config JSON file")
    parser.add_argument("--skip-create", action="store_true", help="Skip issue creation, only sync fields")
    parser.add_argument("--skip-infra", action="store_true", help="Skip milestone/label/day creation")
    args = parser.parse_args()

    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Config file not found: {args.config}")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    week = config["week"]
    print("\n" + "=" * 60)
    print(f"  PhantomNet Sprint Automation v4.0 — Week {week}")
    print("=" * 60)

    # Phase 1: Always validate
    phase1_validate(config)

    if not args.skip_infra:
        # Phase 2-4: Infrastructure
        phase2_milestone(config)
        phase3_labels(config)
        phase4_day_options(config)

    if not args.skip_create:
        # Phase 5-6: Issues
        phase5_create_issues(config)
        phase6_assign_milestone(config)

    # Phase 7: Always sync project
    phase7_sync_project(config)

    print("\n" + "=" * 60)
    print(f"  DONE — Week {week} automation complete.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
