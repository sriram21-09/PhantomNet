# Sprint Issue Automation Template

This document defines the standard template and project properties for all PhantomNet weekly sprint issues (Week 11 onwards).

## 1. Issue Body Template

When generating issues mechanically via Python `gh` scripting or manually, enforce the following structured markdown body exactly:

```markdown
### Objective
[Month X Priority: HIGH/MEDIUM/LOW] - [Brief summary of the primary objective]

### Tasks
- [ ] [Primary Task 1]
  - [Sub-task detail 1]
  - [Sub-task detail 2]
  - [Sub-task detail 3]
- [ ] [Primary Task 2]
  - [Sub-task detail 1]
  - [Sub-task detail 2]

### Deliverables
- [ ] [Key deliverable 1]
- [ ] [Key deliverable 2]

### Estimate
[e.g., 1 day or 1.5 days]
```

## 2. Issue Metadata and Project Fields

All sprint issues must include:
- **Title Format**: `Week XX - Day Y: [Issue Context]`
- **Labels**: Should include `weekXX`, `monthX`, and role-specific/topic-specific labels (e.g., `ml`, `frontend`, `documentation`).
- **Milestone**: Assign to the active Monthly Milestone (e.g., *Month 3 – Phase 3 (Weeks 9–12)*).
- **Project Board**: PhantomNet Workspace (Project V2 ID: 5).

Once added to the Project, the following custom fields must be populated:
1. **Day**: Matches the Day map (e.g., `Mon (Mar 09)`, `Tue (Mar 10)`).
2. **Role**: Base on Assignee. Maps to (`Team Lead`, `Security Developer`, `AI/ML Developer`, `Frontend Developer`).
3. **Type**: Evaluated from title keywords map (`Feature`, `Testing`, `Integration`, `Documentation`, `Review`).
