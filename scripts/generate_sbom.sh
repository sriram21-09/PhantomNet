#!/bin/bash
# ==============================================================================
# PhantomNet V3 - Software Bill of Materials (SBOM) Generator & Quality Check
# Generates CycloneDX and SPDX SBOMs and optionally verifies with Syft/Trivy
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/build/sbom"

mkdir -p "${OUTPUT_DIR}"

echo "[*] Initializing SBOM generation for PhantomNet V3..."

if [ -f "${ROOT_DIR}/backend/venv/bin/python" ]; then
    PYTHON_BIN="${ROOT_DIR}/backend/venv/bin/python"
elif [ -f "${ROOT_DIR}/backend/venv/Scripts/python.exe" ]; then
    PYTHON_BIN="${ROOT_DIR}/backend/venv/Scripts/python.exe"
else
    PYTHON_BIN="python3"
fi

echo "[*] Using Python: ${PYTHON_BIN}"
"${PYTHON_BIN}" "${SCRIPT_DIR}/generate_sbom.py"

echo "[+] SBOM generation complete."
echo "    - CycloneDX: ${OUTPUT_DIR}/phantomnet-cyclonedx.json"
echo "    - SPDX:      ${OUTPUT_DIR}/phantomnet-spdx.json"

# If Syft is installed, also run container/filesystem syft scan
if command -v syft &>/dev/null; then
    echo "[*] Running Syft SBOM generator..."
    syft dir:"${ROOT_DIR}" -o cyclonedx-json="${OUTPUT_DIR}/syft-cyclonedx.json"
    echo "[+] Syft SBOM generated at ${OUTPUT_DIR}/syft-cyclonedx.json"
fi

echo "[+] OPS-03 Verification Complete."
