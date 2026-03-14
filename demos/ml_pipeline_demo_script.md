# ML Pipeline Demo Script - PhantomNet

**Target Audience:** Security Operations Center (SOC) Analysts, ML Engineers  
**Goal:** Demonstrate the end-to-end ML pipeline from event capture to dashboard visualization.  
**Duration:** ~10 Minutes

---

## 1. Introduction (0:00 - 1:30)
- **Visual:** PhantomNet Landing Page / Dashboard.
- **Audio:** "Welcome to the PhantomNet ML Pipeline demonstration. Today we'll look at how we automate threat detection using advanced behavioral analytics."
- **Action:** Open the `ML Insights Dashboard`. Show the `Threat Score Badge` and `Feature Importance`.

## 2. Model Training & Registry (1:30 - 3:30)
- **Visual:** Terminal window with `ModelRegistry` logs.
- **Audio:** "Our pipeline starts with model training. We use our historical dataset to train ensemble models that are then registered and versioned automatically."
- **Action:** 
    - List models using `python ml/registry/model_registry.py --list`.
    - Show metadata for the latest version.

## 3. Automated Evaluation (3:30 - 5:30)
- **Visual:** `reports/evaluation_dashboard.html`.
- **Audio:** "Every model goes through a rigorous automated evaluation phase. We track Accuracy, Precision, and Recall over time."
- **Action:** 
    - Open the HTML dashboard.
    - Point out the `Confusion Matrix` and the `Performance History Timeline`.

## 4. Real-time Inference & Dashboard (5:30 - 8:30)
- **Visual:** Live `ModelMetricsDashboard` with the `Live Engine` toggle ON.
- **Audio:** "Once in production, the model classifies incoming traffic in milliseconds. SOC analysts can see which features are most indicative of current threats."
- **Action:** 
    - Toggle `Live Engine` on/off.
    - Explain how `Packet Size Variance` or `Payload Entropy` changes during a simulated attack.

## 5. Summary & Next Steps (8:30 - 10:00)
- **Visual:** `docs/frontend_ml_integration.md`.
- **Audio:** "We've built a robust foundation for automated detection. In Month 4, we'll finalize the production API integration and scale to multi-node clusters."
- **Action:** Scroll through the integration guide and documentation.

---

**Recording Checklist:**
- [ ] Backend Mock API running (`python backend/mock_ml_api.py`)
- [ ] Model Registry contains at least 3 versions.
- [ ] Browser zoom at 110% for readability.
- [ ] Dark Mode active in IDE and Dashboard.
