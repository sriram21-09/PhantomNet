-- Migration: Add sentinel_llm_enabled to system_config
-- Phase 5 — Sentinel Layer (Week 17, Day 3)
--
-- ⚠️ Adds sentinel_llm_enabled column for dynamic LLM status flag control.

ALTER TABLE system_config ADD COLUMN sentinel_llm_enabled BOOLEAN DEFAULT 0;
