# PhantomNet Reproducibility Audit

## 1. Executive Summary
This audit evaluates the determinism, computational environment, random seed sensitivity, and artifact stability of the PhantomNet research project.

## 2. Seed Variation and Determinism
Evaluation across 5 distinct random seeds using xperiments/run_publication_validation.py:
- Seeds Tested: 42, 123, 2024, 2025, 2026
- Accuracy: 1.0000 across all 5 seeds (std = 0.0)
- F1 Score: 1.0000 across all 5 seeds (std = 0.0)
- ROC-AUC: 1.0000 across all 5 seeds (std = 0.0)
- Conclusion: The zero variance across seeds confirms mathematical determinism, but reflects extreme class separability in the synthetic dataset rather than generalizable robustness.

## 3. Computational Environment
- OS: Windows 11 / Linux (Docker compatible)
- Language: Python 3.11+
- Core Libraries: scikit-learn, joblib, pandas, numpy, fastapi, uvicorn, jinja2, stix2, pytest
- Environment Files: 
equirements.txt, ackend/requirements.txt, docker-compose.yml

## 4. Execution Scripts
- Paper Reproduction: xperiments/reproduce_paper.py (Outputs xperiments/results/paper_metrics.json)
- Validation Suite: xperiments/run_publication_validation.py (Outputs 12 CSV/JSON reports in xperiments/results/publication_validation/)
- DBSCAN Benchmarking: xperiments/results/dbscan_normalization/ (Controlled scaling experiment)

## 5. Artifact Verification Hashes
- Dataset labeled_events_v2_enhanced.csv: 2e22e7cbe8a5c6c36a14bcab8996e25e99f46dad445cc10afef5e68bc9a449e
- Checkpoint AttackClassifier_Enhanced_v1.0.0.pkl: 6812f8ea953c90709428c2a6abd6c90a256dd4f9ec55f77d08aabe5f177cf13b
