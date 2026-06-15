-- Migration: Add detected_signatures to packet_logs
-- Phase 5 — Sentinel Layer (Week 1, Day 1)
-- Issue: #673 (sentinel_service.py will populate this on Day 5)
--
-- ⚠️  This column is STORAGE ONLY at this stage.
--     Population logic lives exclusively in sentinel_service.py.
--     Service type is inferred from dst_port:
--       2222 → SSH | 8080 → HTTP | 2121 → FTP | 2525 → SMTP
--
-- Run automatically via SQLAlchemy Base.metadata.create_all() on startup
-- (SQLite ADD COLUMN is idempotent-safe when run once).

ALTER TABLE packet_logs ADD COLUMN detected_signatures VARCHAR;
