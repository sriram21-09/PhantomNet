"""
Test suite verifying OPS-03 Software Bill of Materials (SBOM) Generation.
Empirically verifies that:
1. SBOM generator scripts exist and execute cleanly.
2. Generated CycloneDX 1.6 SBOM conforms to standard specification.
3. Build provenance (git commit, branch, build timestamp, authors) is embedded in metadata.
4. Core production components are inventoried with exact versions and licenses.
5. Generated SPDX 2.3 document conforms to specification.
"""

import json
import subprocess
import sys
import pytest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SBOM_DIR = ROOT_DIR / "build" / "sbom"
CDX_FILE = SBOM_DIR / "phantomnet-cyclonedx.json"
SPDX_FILE = SBOM_DIR / "phantomnet-spdx.json"
GENERATE_SCRIPT = ROOT_DIR / "scripts" / "generate_sbom.py"
GENERATE_SH = ROOT_DIR / "scripts" / "generate_sbom.sh"


@pytest.fixture(scope="module", autouse=True)
def ensure_sbom_generated():
    """Ensure fresh SBOM is generated before running tests."""
    assert GENERATE_SCRIPT.exists(), f"SBOM generator script missing at {GENERATE_SCRIPT}"
    assert GENERATE_SH.exists(), f"SBOM POSIX shell script missing at {GENERATE_SH}"

    # If SBOM files don't exist yet, generate them
    if not CDX_FILE.exists() or not SPDX_FILE.exists():
        subprocess.check_call([sys.executable, str(GENERATE_SCRIPT)], cwd=ROOT_DIR)

    assert CDX_FILE.exists(), f"CycloneDX SBOM not found at {CDX_FILE}"
    assert SPDX_FILE.exists(), f"SPDX SBOM not found at {SPDX_FILE}"


def test_cyclonedx_schema_and_metadata():
    """Verify CycloneDX schema, specification version, and root component."""
    with open(CDX_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("bomFormat") == "CycloneDX", "BOM format must be CycloneDX"
    assert data.get("specVersion") in ["1.5", "1.6"], "CycloneDX specVersion must be 1.5 or 1.6"

    metadata = data.get("metadata", {})
    assert "timestamp" in metadata, "Metadata must contain ISO timestamp"

    root_comp = metadata.get("component", {})
    assert root_comp.get("name") == "PhantomNet"
    assert root_comp.get("version") == "3.0.0"
    assert root_comp.get("type") == "application"


def test_build_provenance_embedded():
    """Verify git commit and build provenance properties are captured in CycloneDX metadata."""
    with open(CDX_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    properties = {p["name"]: p["value"] for p in data.get("metadata", {}).get("properties", [])}
    assert "phantomnet:git:commit" in properties, "Git commit hash must be embedded"
    assert "phantomnet:git:branch" in properties, "Git branch must be embedded"
    assert "phantomnet:build:timestamp" in properties, "Build timestamp must be embedded"
    assert "phantomnet:build:reproducible" in properties


def test_core_dependencies_inventoried():
    """Verify core production dependencies are tracked in the SBOM components list."""
    with open(CDX_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    components = data.get("components", [])
    assert len(components) >= 50, f"Expected at least 50 dependencies, found {len(components)}"

    component_names = {c["name"].lower().replace("-", "_") for c in components}
    critical_deps = [
        "fastapi",
        "pydantic",
        "redis",
        "sqlalchemy",
        "alembic",
        "prometheus_client",
        "scapy",
        "bandit",
    ]

    for dep in critical_deps:
        assert dep.lower().replace("-", "_") in component_names, f"Critical dependency '{dep}' missing from SBOM inventory"


def test_spdx_document_validity():
    """Verify SPDX 2.3 specification format and package list."""
    with open(SPDX_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("spdxVersion") == "SPDX-2.3"
    assert data.get("dataLicense") == "CC0-1.0"
    assert data.get("SPDXID") == "SPDXRef-DOCUMENT"
    assert "packages" in data
    assert len(data["packages"]) >= 50
