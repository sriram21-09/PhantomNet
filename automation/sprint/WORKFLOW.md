# PhantomNet Sprint Automation v4.0

One-command automation for weekly sprint issue creation and project board sync.

---

## Quick Start

```bash
# Full run — creates everything from scratch:
python automation/sprint/sprint_engine.py --config automation/sprint/week14_config.json

# Sync only — issues already exist, just sync project board:
python automation/sprint/sprint_engine.py --config automation/sprint/week14_config.json --skip-create

# Skip infrastructure — milestone/labels/day options already exist:
python automation/sprint/sprint_engine.py --config automation/sprint/week14_config.json --skip-infra
```

---

## What It Does (7 Phases)

| Phase | Action | Idempotent? |
|---|---|---|
| **1** | Pre-flight validation (gh CLI, config schema) | ✅ |
| **2** | Create milestone if missing | ✅ |
| **3** | Create labels if missing | ✅ |
| **4** | Add Day field options to Project Board if missing | ✅ |
| **5** | Create issues (skip duplicates) | ✅ |
| **6** | Assign milestone to issues without one | ✅ |
| **7** | Add issues to Project Board + sync Role/Type/Day | ✅ |

> All phases are **idempotent** — safe to re-run without creating duplicates.

---

## Config JSON Format

```json
{
    "week": 14,
    "milestone_title": "Month 4 – Sentinel Core (Weeks 13–16)",
    "milestone_description": "Description for new milestone.",
    "month_label": "month-4",
    "extra_labels": [],
    "labels": [
        {"name": "week-14", "color": "1D76DB", "description": "Week 14 tasks"}
    ],
    "day_map": {
        "1": "Mon (Jun 22)",
        "2": "Tue (Jun 23)",
        "3": "Wed (Jun 24)",
        "4": "Thu (Jun 25)",
        "5": "Fri (Jun 26)"
    },
    "tasks": [
        {
            "Day": 1,
            "Role": "Team Lead",
            "Assignee": "sriram21-09",
            "Type": "Feature",
            "Title": "Task Title",
            "Objective": "What this achieves.",
            "Tasks": ["Sub-task 1", "Sub-task 2"],
            "Deliverables": ["path/to/file"],
            "Estimate": 6,
            "Warnings": ["**Do NOT** modify X — reason."]
        }
    ]
}
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `week` | ✅ | Week number (e.g., 14) |
| `milestone_title` | ✅ | Milestone name to create/assign |
| `milestone_description` | ❌ | Description for new milestone |
| `month_label` | ❌ | Month label applied to all issues (e.g., `month-4`) |
| `extra_labels` | ❌ | Additional labels for all issues (e.g., `["sentinel"]`) |
| `labels` | ❌ | Labels to create (name, color, description) |
| `day_map` | ✅ | Maps day number → Day field option string |
| `tasks` | ✅ | Array of task objects |

### Task Object

| Field | Required | Description |
|---|---|---|
| `Day` | ✅ | Day number (1–5) |
| `Role` | ✅ | `Team Lead`, `Security Developer`, `AI/ML Developer`, `Frontend Developer` |
| `Assignee` | ✅ | GitHub username |
| `Type` | ✅ | `Feature`, `Integration`, `Testing`, `Documentation`, `Review` |
| `Title` | ✅ | Task title (no week/day prefix — added automatically) |
| `Objective` | ✅ | What this task achieves |
| `Tasks` | ✅ | Array of sub-task strings |
| `Deliverables` | ✅ | Array of deliverable paths/descriptions |
| `Estimate` | ✅ | Hours estimate (integer) |
| `Warnings` | ❌ | Array of critical implementation warnings |

### Valid Role → Assignee Map

| Role | GitHub Username | Label |
|---|---|---|
| Team Lead | `sriram21-09` | `team-lead` |
| Security Developer | `VivekanandaReddy2006` | `security-dev` |
| AI/ML Developer | `vikranthN101` | `ai-ml-dev` |
| Frontend Developer | `sairammanideepreddy2123` | `frontend-dev` |

---

## Issue Title Format

Generated automatically:
```
Week {X}-Day {Y},{Role},{Title}
```

Examples:
- `Week 14-Day 1,Team Lead,Complete Sentinel Service Orchestrator`
- `Week 14-Day 3,Frontend Developer,Build PlaybookViewer with Markdown`

---

## Project Board Field IDs (Hardcoded)

| Field | ID |
|---|---|
| Day | `PVTSSF_lAHOCn3zZM4BKFg8zg6cR2A` |
| Role | `PVTSSF_lAHOCn3zZM4BKFg8zg6cR9I` |
| Type | `PVTSSF_lAHOCn3zZM4BKFg8zg6cSJQ` |

---

## File Structure

```
automation/sprint/
├── sprint_engine.py       # Main automation engine (v4.0)
├── WORKFLOW.md            # This documentation file
├── config_template.json   # Template for week configs
├── week13_config.json     # Week 13 config (reference)
└── weekXX_config.json     # Per-week config files (created as needed)
```

---

## Error Recovery

| Error | Resolution |
|---|---|
| **API Rate Limit** | Wait 2–5 minutes and re-run (duplicates are auto-skipped) |
| **Milestone not found** | Script creates it automatically |
| **Missing Day Options** | Script creates them automatically via GraphQL |
| **Field Mismatch** | Re-run with `--skip-create` to sync fields only |
| **Encoding errors** | Script uses UTF-8 with error handling — re-run is safe |

---

**Built for PhantomNet — Sentinel V3 Development**
