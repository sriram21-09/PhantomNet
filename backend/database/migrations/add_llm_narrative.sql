-- Migration: Add llm_narrative to sentinel_playbooks
-- Phase 5 — Sentinel Layer (Week 17, Day 1)
--
-- ⚠️ Adds Markdown narrative storage column for AI-generated playbook summaries.

ALTER TABLE sentinel_playbooks ADD COLUMN llm_narrative TEXT;
