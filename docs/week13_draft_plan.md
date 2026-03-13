# Week 13 Draft Plan — Month 4 Kickoff

**Project:** PhantomNet  
**Sprint:** Week 13 (Month 4, Week 1)  
**Priority:** HIGH — Production ML Inference Deployment  
**Date Created:** March 11, 2026

---

## Week 13 Objectives

1. **Deploy ML Inference Service** — Stand up the FastAPI-based inference service with model loading from the `ModelRegistry`.
2. **Integrate Live Honeypot Data** — Connect the feature extraction pipeline to real honeypot event streams.
3. **Establish Production Monitoring** — Set up inference latency, accuracy, and throughput dashboards.
4. **API Endpoint Testing** — Validate all `/api/v2/inference/` endpoints with integration tests.

---

## Daily Breakdown

### Day 1 — Service Scaffolding & Model Loading
| Task | Owner | Priority |
|---|---|---|
| Set up FastAPI project structure under `backend/inference/` | Backend Engineer | HIGH |
| Implement `/api/v2/inference/health` endpoint | Backend Engineer | HIGH |
| Integrate `ModelRegistry` model loader into the service | ML Engineer | HIGH |
| Namespace new routes under `/api/v2/inference/` (no breaking changes to `/api/`) | Full-Stack Engineer | HIGH |

### Day 2 — Prediction Endpoint & Feature Validation
| Task | Owner | Priority |
|---|---|---|
| Implement `/api/v2/inference/predict` endpoint | ML Engineer | HIGH |
| Build feature validation layer (match `FEATURE_EXTRACTION_SPEC_FINAL.md` schema) | Data Engineer | HIGH |
| Implement unified model loader for `.pkl` / `.h5` formats | ML Engineer | MEDIUM |
| Write unit tests for predict endpoint | QA Engineer | MEDIUM |

### Day 3 — Model Management Endpoints & Latency Benchmarking
| Task | Owner | Priority |
|---|---|---|
| Implement `/api/v2/inference/models` and `/models/{version}` endpoints | Backend Engineer | HIGH |
| Implement `/api/v2/inference/models/{version}/promote` and `/rollback` endpoints | Backend Engineer | HIGH |
| Benchmark LSTM inference latency (target: <100ms p95) | ML Engineer | HIGH |
| Set up request logging and metrics collection | DevOps Engineer | MEDIUM |

### Day 4 — Live Data Integration
| Task | Owner | Priority |
|---|---|---|
| Connect honeypot event stream to the feature extraction pipeline | Data Engineer | HIGH |
| Route extracted features to the inference service `/predict` endpoint | Backend Engineer | HIGH |
| Validate end-to-end flow: honeypot event → feature extraction → prediction → response | QA Engineer | HIGH |
| Monitor for feature schema mismatches in live data | Data Engineer | MEDIUM |

### Day 5 — Integration Testing & Documentation
| Task | Owner | Priority |
|---|---|---|
| Run end-to-end integration test suite | QA Engineer | HIGH |
| Validate model promotion and rollback via API | ML Engineer | HIGH |
| Update `docs/api_specification.md` with new inference endpoints | Full-Stack Engineer | MEDIUM |
| Conduct Week 13 retrospective and plan Week 14 | Project Lead | MEDIUM |

---

## Success Criteria

| Metric | Target |
|---|---|
| Inference service uptime | >99% during testing |
| p95 inference latency | <100ms |
| Prediction accuracy on live data | >85% (matching offline benchmarks) |
| All 6 API endpoints passing integration tests | 6/6 |
| Zero breaking changes to existing `/api/` routes | Verified |

---

## Dependencies

- ✅ Model Registry (`ml/registry/model_registry.py`) — Built in Week 11 Day 1
- ✅ Model Comparison & Rollback framework — Built in Week 11 Day 1
- ✅ API Specification (`docs/ml_inference_api_spec.md`) — Drafted in Week 11 Day 2
- ✅ Architecture Diagram (`docs/ml_inference_architecture.png`) — Created in Week 11 Day 2
- ⬜ FastAPI service scaffolding — Week 13 Day 1
- ⬜ Live honeypot event stream connector — Week 13 Day 4

---

## Risks & Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| LSTM latency exceeds 100ms | Medium | Implement model quantization or switch to batch inference |
| Feature schema mismatch with live data | High | Feature validation layer with clear error reporting |
| Model drift in production | Low (Week 13) | Monitoring dashboards with automated alerting |
