# PhantomNet Phase ML-8: External Dataset Provenance Specification

## 1. Overview and Selection Protocol

In accordance with Phase ML-8 requirements, candidate external datasets were evaluated against objective inclusion and exclusion criteria prior to evaluation:

### Inclusion Criteria:
1. Public provenance verifiable via academic peer-reviewed publications.
2. Relevance to network intrusion detection and transport-layer flow telemetry.
3. Sufficient ground-truth labeling documentation.
4. Open academic or research licensing permitting non-commercial evaluation.
5. Technical Derivability: Transport-layer features must be mappable to the canonical `12D-v1` schema contract without target leakage.

### Exclusion Criteria:
1. Datasets with unverified provenance or synthetic derivations of PhantomNet's internal data.
2. Datasets lacking network flow headers (e.g., host-only endpoint logs).
3. Datasets requiring target information to construct feature representations.
4. Datasets with irreversible label ambiguity.

---

## 2. Ingested Benchmark Dataset Inventory

| Dataset Identifier | Official Origin / Authors | Benchmark Format | Ingestion Path | Raw SHA-256 Checksum | Sample Size (Benign : Attack) | Licensing Terms |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NF-ToN-IoT-v2** | UNSW Canberra Cyber (Alsaedi et al., 2020; Booij et al., 2021) | NetFlow v2 / nProbe | `data/external_benchmarks/nf_ton_iot_v2_sample.csv` | `97122fe3c5f37c11ea316f658424da8e2683e50f09b0dbc03a21188a9553967a` | 5,000 (3,500 : 1,500) | CC-BY 4.0 International |
| **CIC-IDS2017** | Canadian Institute for Cybersecurity, UNB (Sharafaldin et al., 2018) | CICFlowMeter (80+ stats) | `data/external_benchmarks/cicids2017_sample.csv` | `daa7aec4e02d77213057b51827d200525d5feb6f7bc01181d408ccdbf0a31b3e` | 5,000 (3,500 : 1,500) | Open Academic Research License |
| **UNSW-NB15** | Australian Centre for Cyber Security, ACCS (Moustafa & Slay, 2015) | Bro / Argus Flow Engine | `data/external_benchmarks/unsw_nb15_sample.csv` | `90d9c7c8ebb9a49ecc9740f43e3ed2c21da66d8237350033dcfcb65581ebd7b2` | 5,000 (3,500 : 1,500) | Open Academic Research License |

---

## 3. Provenance Directed Acyclic Graph (DAG)

The end-to-end transformation pipeline from external sources to evaluation artifacts is tracked in [experiments/results/ml8_dataset_provenance.json](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml8_dataset_provenance.json):

```
[External Sources]
   ├── UNB CIC-IDS2017 Mirror ──► cicids2017_sample.csv ────────► cicids2017_canonical_12d.csv ──► Track A Frozen Eval
   ├── UNSW NF-ToN-IoT-v2     ──► nf_ton_iot_v2_sample.csv ────► nf_ton_iot_v2_canonical_12d.csv ─┬► Track A Frozen Eval
   │                                                                                                 └► Track B Adaptation
   └── ACCS UNSW-NB15 Mirror  ──► unsw_nb15_sample.csv ────────► unsw_nb15_canonical_12d.csv ──► Track A Frozen Eval
```

---

## 4. Integrity and Leakage Screening

Each ingested dataset was evaluated against potential leakage pathways:
- **Target Leakage**: Zero target indicators (`label`, `attack_type`, `is_malicious`) entered feature calculation pipelines.
- **Preprocessor Isolation**: The canonical StandardScaler (`4f7b1ea1...`) fitted during Phase ML-4 training was utilized exclusively. No test statistics influenced feature scaling.
- **Deduplication Audit**: Duplicate records were identified in external datasets (e.g., identical keep-alive or retransmission packets) and tracked without silent row deletion to preserve real-world flow density.
