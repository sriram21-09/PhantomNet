# PhantomNet ML-5: Performance Evaluation Protocol

## 1. Purpose

Defines the exact protocol for evaluating PhantomNet model performance,
ensuring reproducibility and preventing post-hoc metric selection.

---

## 2. Benchmark Dataset

| Property | Value |
|:---|:---|
| File | `data/remediated_dataset_v3.csv` |
| SHA-256 | `390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363` |
| Samples | 5,000 |
| Features | 12 (canonical 12D-v1 schema) |
| Classes | 0=benign (3,500), 1=malicious (1,500) |
| Class ratio | 70/30 |
| Provenance | `scripts/generate_remediated_dataset.py` (seed=42) |

---

## 3. Splitting Protocol

| Property | Value |
|:---|:---|
| Method | Stratified train/test split |
| Ratio | 80% train (4,000) / 20% test (1,000) |
| Repetitions | N=30 independent Monte Carlo splits |
| Seeds | 100, 101, …, 129 |
| Stratification | Preserves 70/30 class ratio per split |

---

## 4. Preprocessing Protocol

1. Initialize `StandardScaler()` fresh per run
2. Fit on X_train ONLY (`scaler.fit_transform(X_train)`)
3. Transform X_test using training parameters (`scaler.transform(X_test)`)
4. No feature selection, PCA, or dimensionality reduction

---

## 5. Model Configurations

### 5.1 Random Forest
```python
RandomForestClassifier(
    n_estimators=100,
    max_depth=12,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=seed,
    n_jobs=1,
)
```

### 5.2 Isolation Forest
```python
IsolationForest(
    n_estimators=100,
    contamination=0.10,
    random_state=seed,
    n_jobs=1,
)
```

### 5.3 Ensemble
```
S = 0.85 × P_RF + 0.15 × S_IF
Prediction: malicious if S ≥ 0.50
```

---

## 6. Metrics Collected Per Run

| Metric | Definition |
|:---|:---|
| Accuracy | (TP+TN) / N |
| Precision | TP / (TP+FP) |
| Recall | TP / (TP+FN) |
| F1 | 2·P·R / (P+R) |
| Specificity | TN / (TN+FP) |
| FPR | FP / (FP+TN) |
| FNR | FN / (FN+TP) |
| ROC-AUC | Area under ROC curve |
| PR-AUC | Average precision score |
| Confusion matrix | TN, FP, FN, TP |

---

## 7. Reporting Standards

1. Report **all individual run metrics** (not only means)
2. Report mean ± standard deviation across N=30 runs
3. Report 95% confidence intervals (t-distribution, df=29)
4. Clearly distinguish SD (variability) from SE (uncertainty of mean)
5. Report paired statistical tests with effect sizes
6. Apply Holm-Bonferroni correction for multiple comparisons
7. Report non-significant results honestly

---

## 8. Prohibited Practices

- ❌ Reporting only favorable metrics
- ❌ Changing thresholds after inspecting test results
- ❌ Changing model architecture to improve metrics
- ❌ Removing difficult test observations
- ❌ Fabricating statistical significance
- ❌ Manually entering p-values or confidence intervals
- ❌ Selecting metrics because they produce favorable results

---

## 9. Execution

```bash
# Generate all ML-5 artifacts
python scripts/generate_ml5_statistics.py

# Run ML-5 test suite
python -m pytest tests/experiments/test_ml5_model_statistics.py -v

# Run full reproduction
python experiments/reproduce_all.py
```
