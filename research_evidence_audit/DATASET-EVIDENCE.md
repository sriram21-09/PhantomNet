# PhantomNet Dataset Evidence

## 1. Inventory of Datasets in Repository
1. ackend/ml/datasets/labeled_events_v2_enhanced.csv:
   - Rows: 5,000 | Columns: 13
   - Distribution: 1,512 Benign (30.24%), 3,488 Malicious (69.76%)
   - Hash: SHA256 2e22e7cbe8a5c6c36a14bcab8996e25e99f46dad445cc10afef5e68bc9a449e
   - Nature: 100% Synthetic, generated via ackend/ml/update_dataset.py.
2. data/training_dataset.csv:
   - Rows: 1,000 | Columns: 16 (15 flow features + label)
   - Nature: Early synthetic flow dataset.
3. data/ground_truth.csv:
   - Rows: 100 | Columns: 14
   - Nature: Handcrafted test fixtures for integration assertions.
4. Operational Telemetry:
   - ackend/database/phantomnet.db (Honeypot event tables).
   - ackend/database/sentinel.db (Incident and playbook state tables).

## 2. Generator Code Audit (update_dataset.py)
The dataset generation logic uses fixed static templates:
- **Benign Generator:** Repeatedly generates GET /index.html HTTP/1.1. Every single sample has length 24 and Shannon entropy 3.7317.
- **Malicious Generator:** Selects uniformly from 5 attack strings:
  1. SQLi: ' OR '1'='1' --
  2. XSS: <script>alert(1)</script>
  3. Path Traversal: ../../../../etc/passwd
  4. Command Injection: ; cat /etc/shadow
  5. Credential Attack: dmin:admin123
- **Resulting Flaw:** The classification problem is reduced to detecting whether string length == 24 or != 24. No generalization to unseen benign or attack traffic is measured.
