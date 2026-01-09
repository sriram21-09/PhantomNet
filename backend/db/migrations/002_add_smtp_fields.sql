-- MIGRATION: 002_Add_SMTP_Fields
-- DESCRIPTION: Expands packet_logs to support detailed SMTP analysis
-- AUTHOR: PhantomNet Architect
-- DATE: 2026-01-09

-- 1. Add SMTP-specific columns to the main table
ALTER TABLE packet_logs ADD COLUMN IF NOT EXISTS mail_from VARCHAR(255);
ALTER TABLE packet_logs ADD COLUMN IF NOT EXISTS rcpt_to VARCHAR(255);
ALTER TABLE packet_logs ADD COLUMN IF NOT EXISTS email_subject TEXT;
ALTER TABLE packet_logs ADD COLUMN IF NOT EXISTS body_len INTEGER DEFAULT 0;

-- 2. Add Indexes for high-speed searching
-- (Crucial for queries like "Find all emails sent to admin@company.com")
CREATE INDEX IF NOT EXISTS idx_mail_from ON packet_logs(mail_from);
CREATE INDEX IF NOT EXISTS idx_rcpt_to ON packet_logs(rcpt_to);

-- 3. Update the Attack Types to include SMTP
-- (This is documentation for the Enum, Postgres doesn't strictly enforce string enums unless specified)
-- New Types: 'SMTP_RELAY', 'SPAM_BOT', 'PHISHING_ATTEMPT'