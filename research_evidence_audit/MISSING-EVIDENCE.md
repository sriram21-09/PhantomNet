# PhantomNet Missing Evidence Catalog

The following empirical evidence is currently absent from the repository and must be obtained before paper submission:

1. **Real Honeypot Deployment Data:**
   - Current status: 100% of evaluation data is synthetic.
   - Gap: No evidence of live attacker interaction from a public cloud IP deployment.
2. **Standard Benchmark Baseline Comparisons:**
   - Current status: No evaluation on public cybersecurity benchmarks.
   - Gap: Missing comparative evaluation against CIC-IDS2017, UNSW-NB15, or NSL-KDD.
3. **Multi-Class Attack Categorization:**
   - Current status: Only binary detection (Benign vs Malicious) is evaluated.
   - Gap: Models do not classify specific attack families or techniques.
4. **Trained Deep Learning Weights:**
   - Current status: ackend/ml/lstm_attack_predictor.py is a mock heuristic placeholder.
   - Gap: No PyTorch or TensorFlow model weights or loss curves exist.
5. **Adversarial Robustness Testing:**
   - Current status: Zero adversarial perturbation or evasion tests conducted.
   - Gap: Vulnerability to payload padding, low-and-slow interval stretching, and user-agent spoofing is unmeasured.
6. **Ablation on Non-Trivial Datasets:**
   - Current status: Ablation studies on synthetic data show Ensemble = Random Forest because RF achieves 100%.
   - Gap: Value of the 0.3 Isolation Forest weight has not been demonstrated on realistic, overlapping distributions.
