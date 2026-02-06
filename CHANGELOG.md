# Changelog

## Week 2 – Dec 2025
### Added
- SSH Honeypot
- HTTP Honeypot
- Events API
- Stats API
- Dashboard metrics

### Fixed
- DB schema mismatches
- API response issues
- Dashboard fetch errors

### Improved
- Logging structure
- Error handling
- API consistency


# Changelog

All notable changes to the PhantomNet project are documented in this file.

The format follows:
- Feature additions
- Enhancements
- Fixes
- Tests & CI
- Documentation

---

## [v0.3-week7-ai-engine] - 2026-02-05

### 🚀 Features
- Implemented full ML model lifecycle using MLflow
  - Model training, evaluation, and logging
  - Model registry integration
  - Versioning with staging lifecycle
- Added secure model deployment pipeline using MLflow Registry
- Built threat intelligence correlation engine
  - External feed ingestion (mock + extensible design)
  - IOC and ML prediction correlation
  - Correlation scoring logic
  - CLI-based correlation API

### 🧠 Machine Learning
- Binary attack detection model
- Accuracy consistently ≥ 85%
- Inference latency consistently < 100ms
- MLflow experiment tracking enabled
- Model lineage, metadata, and tags tracked

### 🔗 Integrations
- Integrated ML pipeline with PhantomNet backend
- Integrated threat intelligence pipeline with ML predictions
- Unified execution paths for standalone and integrated runs

### 🧪 Tests & Quality
- Added unit tests for:
  - Model training
  - Model registry validation
  - Deployment and inference
- Added integration tests for:
  - End-to-end ML pipeline
  - Latency and accuracy validation
- All tests passing (warnings only, no failures)

### 🔄 CI/CD
- Added GitHub Actions workflow for ML pipeline
- Automated checks:
  - Dependency install
  - Test execution
  - Pipeline validation

### 📚 Documentation
- Added Week 7 Day 3 documentation for model lifecycle
- Added Week 7 Day 4 documentation for threat correlation pipeline
- Updated project changelog with release details

### 🏷 Release
- Created release tag: `v0.3-week7-ai-engine`
- Ready for next phase integration

---

## [v0.2-week6-ml-core]

- Initial ML pipeline
- Dataset preprocessing
- Baseline model training and evaluation

---

## [v0.1-initial]

- Project structure initialized
- Backend scaffolding created

