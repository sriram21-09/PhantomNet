# DECISIONS.md — Architecture Decision Records

> **Purpose**: Log significant technical decisions and their rationale.

## Decisions

### [DECISION-001] GSD Workflow System Selection

**Date**: 2026-06-12
**Status**: Accepted

#### Context
The developer and agent need a structured, predictable process for planning, executing, verifying, and mapping project phases.

#### Decision
Adopt the GSD (Get Shit Done) workflows for Antigravity, including structured `.gsd/` documentation (SPEC.md, ROADMAP.md, STATE.md, ARCHITECTURE.md, STACK.md) and standardized workflows.

#### Rationale
Enforces quality gates (e.g. Planning Lock, Verification) and maps codebases cleanly, reducing communication gaps and improving execution speed.

#### Consequences
Requires maintaining project state documents in `.gsd/` folder, adding atomic commits, and verifying deliverables before completing milestones.

---

*Last updated: 2026-06-12*
