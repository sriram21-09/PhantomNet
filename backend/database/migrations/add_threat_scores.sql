-- Migration: Add threat_level and anomaly_score to packet_logs

-- Add threat_level column (e.g. HIGH, MEDIUM, LOW)
ALTER TABLE packet_logs ADD COLUMN threat_level VARCHAR(16);

-- Add anomaly_score column (Raw output from IsolationForest, distinct from normalized threat_score)
ALTER TABLE packet_logs ADD COLUMN anomaly_score FLOAT;

-- Create index for faster filtering by threat level
CREATE INDEX ix_packet_logs_threat_level ON packet_logs (threat_level);
