import json
import os
import shutil
from typing import Dict, List, Optional, Any
import datetime
import re


class ModelRegistry:
    """
    Manages model versioning, metadata, and storage.
    Uses versioning scheme: v{major}.{minor}.{patch}
    """

    def __init__(self, registry_dir: str = "ml_models/registry"):
        self.registry_dir = registry_dir
        self.index_file = os.path.join(registry_dir, "models_index.json")
        self._ensure_registry_exists()

    def _ensure_registry_exists(self):
        """Creates the registry directory and empty index if they don't exist."""
        os.makedirs(self.registry_dir, exist_ok=True)
        if not os.path.exists(self.index_file):
            self._save_index({"models": {}})

    def _load_index(self) -> Dict[str, Any]:
        with open(self.index_file, "r") as f:
            return json.load(f)

    def _save_index(self, index_data: Dict[str, Any]):
        with open(self.index_file, "w") as f:
            json.dump(index_data, f, indent=4)

    def _parse_version(self, version: str) -> tuple:
        """Parses a version string like 'v1.2.3' into (major, minor, patch)."""
        match = re.match(r"^v(\d+)\.(\d+)\.(\d+)$", version)
        if not match:
            raise ValueError(
                f"Invalid version format: {version}. Expected v{{major}}.{{minor}}.{{patch}}"
            )
        return int(match.group(1)), int(match.group(2)), int(match.group(3))

    def _format_version(self, major: int, minor: int, patch: int) -> str:
        return f"v{major}.{minor}.{patch}"

    def get_latest_version(self) -> Optional[str]:
        """Returns the highest version string in the registry."""
        index = self._load_index()
        versions = list(index["models"].keys())
        if not versions:
            return None

        # Sort versions by parsed tuple (major, minor, patch)
        versions.sort(key=self._parse_version, reverse=True)
        return versions[0]

    def increment_version(self, bump_type: str = "patch") -> str:
        """
        Calculates the next version string.
        bump_type can be 'major', 'minor', or 'patch'.
        """
        latest = self.get_latest_version()
        if not latest:
            return "v1.0.0"

        major, minor, patch = self._parse_version(latest)

        if bump_type == "major":
            return self._format_version(major + 1, 0, 0)
        elif bump_type == "minor":
            return self._format_version(major, minor + 1, 0)
        elif bump_type == "patch":
            return self._format_version(major, minor, patch + 1)
        else:
            raise ValueError("bump_type must be 'major', 'minor', or 'patch'")

    def register_model(
        self,
        model_path: str,
        model_name: str,
        bump_type: str = "patch",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Registers a new model version.
        Args:
            model_path: The local path to the trained model file (e.g., .pkl or .h5).
            model_name: A descriptive name for the model type (e.g., "LSTM_Anomaly_Detector").
            bump_type: 'major', 'minor', or 'patch' to determine the next version.
            metadata: Features, accuracy, hyperparameters, etc.
        Returns:
            The newly registered version string.
        """
        index = self._load_index()
        new_version = self.increment_version(bump_type)

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        # Determine destination in registry
        ext = os.path.splitext(model_path)[1]
        dest_filename = f"{model_name}_{new_version}{ext}"
        dest_path = os.path.join(self.registry_dir, dest_filename)

        # Copy the model artifact
        shutil.copy2(model_path, dest_path)

        # Prepare metadata schema
        model_metadata = {
            "version": new_version,
            "name": model_name,
            "training_date": datetime.datetime.now().isoformat(),
            "path": dest_path,
            "status": "Staging",  # Default status
            "metrics": metadata.get("metrics", {}) if metadata else {},
            "features": metadata.get("features", []) if metadata else [],
            "hyperparameters": metadata.get("hyperparameters", {}) if metadata else {},
        }

        # Update index
        index["models"][new_version] = model_metadata
        self._save_index(index)

        return new_version

    def get_model(self, version: str) -> Optional[Dict[str, Any]]:
        """Retrieves metadata for a specific version."""
        index = self._load_index()
        return index["models"].get(version)

    def get_model_by_status(self, status: str) -> Optional[Dict[str, Any]]:
        """Retrieves the highest version model with the given status."""
        index = self._load_index()
        matching_models = [
            m for m in index["models"].values() if m.get("status") == status
        ]
        if not matching_models:
            return None

        matching_models.sort(
            key=lambda x: self._parse_version(x["version"]), reverse=True
        )
        return matching_models[0]

    def update_model_status(self, version: str, new_status: str):
        """Updates the status (e.g., Staging -> Production, or Production -> Archived)."""
        index = self._load_index()
        if version not in index["models"]:
            raise ValueError(f"Version {version} not found in registry.")

        index["models"][version]["status"] = new_status
        self._save_index(index)
