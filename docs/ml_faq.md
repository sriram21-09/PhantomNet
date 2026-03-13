# ML System FAQ - PhantomNet

This document answers common questions regarding the Machine Learning infrastructure within the PhantomNet platform.

---

### Q1: How do I train a new model version?
**A:** Use the `ml/training/train_model.py` script. It will automatically load the latest labeled dataset, perform feature engineering, and register the resulting artifact in the `ModelRegistry`.

### Q2: What is the "Threat Score" and how is it calculated?
**A:** The Threat Score is a normalized value (0-100) derived from the model's prediction confidence and the severity of the identified attack pattern. A score > 80 typically indicates a high-confidence match for a known malicious signature or anomaly.

### Q3: Why is my Accuracy high but Detection Rate low?
**A:** This is often due to **Class Imbalance**. If 99% of your traffic is benign, a model that predicts "benign" for everything will be 99% accurate but useless for security. We use F1-Score and Recall as our primary metrics to ensure we are actually catching attacks.

### Q4: How do I rollback to a previous model?
**A:** The `ModelRegistry` supports versioning. You can use the `reg.promote_model(version)` command to set a previous version to "Production". The dashboard will automatically pick up the change during the next polling cycle.

### Q5: Can I add new features to the model?
**A:** Yes. Update the `backend/ml/feature_extractor.py` to include your new logic. Remember that any change in features requires a retrain of all models to avoid "Feature Mismatch" errors at inference time.

### Q6: What does "Payload Entropy" signify?
**A:** Entropy measures the randomness of data. High entropy in packet payloads is often a sign of encryption or obfuscation, which can be common in Exfiltration or Command & Control (C2) traffic.

### Q7: Is the system capable of real-time detection?
**A:** Currently, the system supports "near-real-time" detection with inference times under 50ms per batch. The Month 4 plan includes shifting to a full stream-processing architecture for sub-10ms response times.
