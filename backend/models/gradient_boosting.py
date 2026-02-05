"""
Gradient Boosting Classifier
----------------------------
Purpose:
- Supervised baseline model for PhantomNet
- SOC-first: prioritize recall on malicious traffic
"""

from sklearn.ensemble import GradientBoostingClassifier


def build_gradient_boosting_model(random_state: int = 42) -> GradientBoostingClassifier:
    """
    Build a stable Gradient Boosting classifier.
    """

    model = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.05,
        max_depth=3,
        subsample=1.0,          # IMPORTANT: avoid class trimming
        random_state=random_state
    )

    return model
