import unittest
import os
import shutil
from ml.registry.model_registry import ModelRegistry
from ml.evaluation.model_comparator import ModelComparator

class TestRollbackFramework(unittest.TestCase):
    
    def setUp(self):
        self.test_registry_dir = "ml_models/test_rollback_registry"
        if os.path.exists(self.test_registry_dir):
            shutil.rmtree(self.test_registry_dir)
        self.registry = ModelRegistry(registry_dir=self.test_registry_dir)
        
        # Create a dummy model file
        os.makedirs("ml_models", exist_ok=True)
        self.dummy_model_path = "ml_models/dummy.pkl"
        with open(self.dummy_model_path, "w") as f:
            f.write("dummy")

    def tearDown(self):
        if os.path.exists(self.test_registry_dir):
            shutil.rmtree(self.test_registry_dir)
        if os.path.exists(self.dummy_model_path):
            os.remove(self.dummy_model_path)

    def test_performance_degradation_rollback(self):
        """
        Scenario: A new model (v1.1.0) is trained and staged.
        We run a comparator against the production model (v1.0.0).
        If v1.1.0 performs significantly worse, we rollback (mark status as Deprecated)
        and keep v1.0.0 as Production.
        """
        # 1. Register base stable model
        v1_meta = {"metrics": {"accuracy": 0.88, "f1_score": 0.85}}
        v1 = self.registry.register_model(self.dummy_model_path, "Dummy", bump_type="major", metadata=v1_meta)
        self.registry.update_model_status(v1, "Production")
        
        # 2. Register degraded new model
        v2_meta = {"metrics": {"accuracy": 0.70, "f1_score": 0.65}} # Significant degradation
        v2 = self.registry.register_model(self.dummy_model_path, "Dummy", bump_type="minor", metadata=v2_meta)
        self.registry.update_model_status(v2, "Staging")
        
        # 3. Simulate Evaluation Gate
        comparator = ModelComparator(self.registry)
        diff = comparator.compare_models(v1, v2)
        
        accuracy_drop = diff["accuracy"]["difference"]
        
        # 4. Trigger automated rollback logic if drop is too large
        ROLLBACK_THRESHOLD = -0.05
        if accuracy_drop < ROLLBACK_THRESHOLD:
            # Drop is severe (-0.18), initiate rollback
            self.registry.update_model_status(v2, "Archived")
            # Production model remains v1.0.0
            
        # 5. Assertions
        active_prod = self.registry.get_model_by_status("Production")
        self.assertIsNotNone(active_prod)
        self.assertEqual(active_prod["version"], v1)
        
        failed_model = self.registry.get_model(v2)
        self.assertEqual(failed_model["status"], "Archived")

    def test_bug_triggered_rollback(self):
        """
        Scenario: A model is promoted to Production but a critical bug is discovered
        (e.g., it crashes on certain input types). Operator manually rolls it back.
        """
        # 1. Register and promote v1
        v1_meta = {"metrics": {"accuracy": 0.90, "f1_score": 0.88}}
        v1 = self.registry.register_model(self.dummy_model_path, "Dummy", bump_type="major", metadata=v1_meta)
        self.registry.update_model_status(v1, "Production")

        # 2. Register and promote v2 (looks good on metrics)
        v2_meta = {"metrics": {"accuracy": 0.92, "f1_score": 0.90}}
        v2 = self.registry.register_model(self.dummy_model_path, "Dummy", bump_type="minor", metadata=v2_meta)
        self.registry.update_model_status(v1, "Archived")  # Demote old
        self.registry.update_model_status(v2, "Production")  # Promote new

        # 3. Bug discovered in v2! Manual rollback: archive v2, restore v1
        self.registry.update_model_status(v2, "Archived")
        self.registry.update_model_status(v1, "Production")

        # 4. Assertions
        active_prod = self.registry.get_model_by_status("Production")
        self.assertIsNotNone(active_prod)
        self.assertEqual(active_prod["version"], v1)

        buggy_model = self.registry.get_model(v2)
        self.assertEqual(buggy_model["status"], "Archived")

    def test_successful_promotion_no_rollback(self):
        """
        Negative test: When a new model is genuinely better, it should be promoted
        and no rollback should occur.
        """
        # 1. Register stable v1
        v1_meta = {"metrics": {"accuracy": 0.85, "f1_score": 0.82}}
        v1 = self.registry.register_model(self.dummy_model_path, "Dummy", bump_type="major", metadata=v1_meta)
        self.registry.update_model_status(v1, "Production")

        # 2. Register improved v2
        v2_meta = {"metrics": {"accuracy": 0.91, "f1_score": 0.89}}
        v2 = self.registry.register_model(self.dummy_model_path, "Dummy", bump_type="minor", metadata=v2_meta)
        self.registry.update_model_status(v2, "Staging")

        # 3. Evaluate — improvement detected, promote
        comparator = ModelComparator(self.registry)
        diff = comparator.compare_models(v1, v2)
        accuracy_change = diff["accuracy"]["difference"]

        ROLLBACK_THRESHOLD = -0.05
        if accuracy_change < ROLLBACK_THRESHOLD:
            self.registry.update_model_status(v2, "Archived")
        else:
            # Promote: archive old, activate new
            self.registry.update_model_status(v1, "Archived")
            self.registry.update_model_status(v2, "Production")

        # 4. Assertions — v2 should now be Production
        active_prod = self.registry.get_model_by_status("Production")
        self.assertEqual(active_prod["version"], v2)
        self.assertEqual(self.registry.get_model(v1)["status"], "Archived")

if __name__ == "__main__":
    unittest.main()
