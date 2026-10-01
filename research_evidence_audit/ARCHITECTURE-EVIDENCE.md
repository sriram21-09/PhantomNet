# PhantomNet Architecture Evidence

## 1. Deception Ingestion Layer
PhantomNet implements active multi-protocol deception services:
- **SSH Honeypot:** Custom / Paramiko SSH daemon bound to port 2222. Simulates interactive terminal and logs auth attempts and executed shell commands.
- **HTTP Honeypot:** Async aiohttp / Flask server bound to port 8080. Emulates standard web application endpoints and records headers, paths, parameters, and payloads.
- **FTP Honeypot:** Pyftpdlib daemon bound to port 2121. Captures anonymous logins and file exfiltration attempts.
- **SMTP Honeypot:** Aiosmtpd server bound to port 2525. Records HELO handshakes and mail payload headers.

## 2. Storage & Persistence Architecture
- **Primary Database:** SQLite 3 database located at ackend/database/phantomnet.db (events, sessions, attackers).
- **Incident Database:** SQLite 3 database located at ackend/database/sentinel.db (incidents, playbooks, MITRE tags).
- **Concurrency & Integrity:** WAL mode (PRAGMA journal_mode = WAL;) and busy timeouts (PRAGMA busy_timeout = 5000;) are active to permit concurrent honeypot writes and analytics polling.

## 3. Feature Pipeline & Semantic Inconsistency
- **Feature Set A (15 Dimensions):** Implemented in ackend/ml/feature_extractor.py. Extracts network flow metrics (packet lengths, inter-arrival variance, protocol encoding, burst rates).
- **Feature Set B (12 Dimensions):** Implemented in ackend/ml/feature_engineering_v2.py. Extracts host session behavioral indicators (command counts, payload entropy, failed logins, traversal counts).
- **Architectural Disconnect:** ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl was trained on Feature Set B, but runtime modules slice Feature Set A arrays using iloc[:, :12], creating a semantic feature mismatch during live inference.
