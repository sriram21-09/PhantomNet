# SPEC.md — Project Specification

> **Status**: `FINALIZED`

## Vision
PhantomNet is a production-grade, AI-driven active network defense and deception platform. By combining real-time packet sniffing, machine learning threat analysis (Random Forest & LSTM), decoy honeypots (SSH, HTTP, FTP, SMTP), and an active firewall response layer, PhantomNet shifts cybersecurity from passive log monitoring to active, automated defense. All systems are coordinated through a real-time React-based security dashboard.

## Goals
1. **Real-Time Deception & Intelligence** — Intercept and decoy unauthorized scan/intrusion attempts to safe, logging-hardened honeypot interfaces.
2. **AI-Driven Traffic Classification** — Evaluate network logs using ML classifiers (Random Forest & LSTM) to yield real-time threat scores and attack attribution.
3. **Automated Active Response** — Expose automated response APIs that block attacking IPs dynamically at the OS firewall layer.
4. **Comprehensive Security Dashboard** — Present real-time maps, events, system metrics, and topology configurations to security operators.
5. **Sprint Rollout Automation** — Automate task tracking, issue creation, and project board syncing for the Sentinel Core phase via `sprint_engine.py`.

## Non-Goals (Out of Scope)
- Building a commercial, general-purpose SIEM (focused on prototype mesh simulation).
- Developing custom hypervisors (runs on standard container/Mininet topologies).

## Constraints
- Must run in python 3.10+ environments.
- Frontend uses React 19 and Tailwind CSS v4.
- Integration testing relies on `gh` CLI credentials and authenticated access for project boards.

## Success Criteria
- [ ] Successful automation of week 14-16 sprint task and issue generation.
- [ ] 100% synchronization of Day/Role/Type fields on the GitHub Project Board.
- [ ] Real-time updates pushed to the dashboard via WebSockets.
- [ ] Clean isolation of honeypot logs to prevent pollution of production metrics.

---

*Last updated: 2026-06-12*
