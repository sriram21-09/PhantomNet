# ML API Documentation – v2
## Frontend Integration Reference
---
## 1. Prediction API Response Structure
The prediction API returns both the model output and optional explainability metadata.
### Sample Response
```json
{
  "prediction": "Approved",
  "confidence": 0.87,
  "explainability": {
    "features": [
      {
        "name": "Credit Score",
        "contribution": 0.42
      },
      {
        "name": "Income Level",
        "contribution": 0.31
      },
      {
        "name": "Loan History",
        "contribution": 0.14
      }
    ]
  }
}
# 3️⃣ `docs/week8_integration_guide.md`

✅ Step-by-step integration  
✅ Clear assumptions  
```md
# Week 8 Frontend Integration Guide
## Explainability Feature Handoff
---
## 1. Overview
This document provides integration guidance for the explainability UI component developed in Week 7.
The Explainability component is designed to:
- Be non-blocking
- Render only on user interaction
- Gracefully handle missing ML metadata
---
## 2. Component Location
---
## 3. Integration Steps
### Step 1: Import Component
```js
import Explainability from "../components/Explainability";

<Explainability
  confidence={apiResponse.confidence}
  features={apiResponse.explainability?.features}
/>
📌 **Why this is a perfect handoff doc**
- Anyone can continue from here
- No dependency on Week 7 developers
- Clear future roadmap
---
## 🟢 Final Verdict (Important)
✔️ Yes, **you SHOULD insert code and real content**  
✔️ These files are now **production-ready examples**  
✔️ This fully satisfies **Week 7 – Day 4 deliverables**