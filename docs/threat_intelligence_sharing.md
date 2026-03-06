# Threat Intelligence Sharing Framework

PhantomNet includes an automated framework for extracting, classifying, and sharing Indicators of Compromise (IOCs) detected via its honeypot network. This framework follows industry standards like STIX 2.1 and integrates with major threat intelligence platforms.

## 🏗️ Architecture

The sharing framework consists of three main components:

1.  **IOC Extractor (`backend/services/ioc_extractor.py`)**:
    -   Uses advanced regex to identify IPs, Domains, URLs, File Hashes (MD5, SHA-1, SHA-256), and Email Addresses from raw honeypot payloads.
    -   Classifies threats into categories like *Malware C2*, *Phishing*, *Scanner IP*, and *Brute Force Source*.
    -   Calculates confidence scores based on detection frequency and source reliability.

2.  **STIX Export Module (`backend/services/stix_exporter.py`)**:
    -   Converts extracted IOCs into the **STIX 2.1** standard.
    -   Generates full STIX Bundles containing `Indicator` objects with proper patterns and meta-data.
    -   Provides standardized output for ingestion by other security tools (SIEM, SOAR, TIP).

3.  **Threat Intelligence Service (`backend/services/threat_intel.py`)**:
    -   **MISP Integration**: Automatically pushes IOCs to a connected MISP instance using `PyMISP`.
    -   **AlienVault OTX Integration**: Submits indicators to OTX Pulses via the official OTX API.
    -   **Public Community Feed**: Generates a daily JSON report (`reports/daily_threat_feed.json`) for sharing with the community or via GitHub.

## 🚀 Usage

### Enabling Integrations

To enable sharing to MISP and AlienVault OTX, add the following to your `.env` file:

```env
# MISP Configuration
MISP_URL=https://your-misp-instance.com
MISP_KEY=your_misp_api_key

# AlienVault OTX Configuration
ALIENVAULT_OTX_KEY=your_otx_api_key
```

### Manual Export

You can trigger a manual STIX export or report generation via the `ThreatIntelService` in the backend:

```python
from backend.services.threat_intel import threat_intel_service
from backend.services.ioc_extractor import ioc_extractor

# Process events and generate report
iocs = ioc_extractor.process_event(some_honeypot_event)
threat_intel_service.generate_daily_report(iocs)
```

## 📊 Sample STIX Export

Extracted IOCs are formatted as follows in the STIX 2.1 Bundle:

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--...",
    "name": "Malware C2",
    "pattern": "[ipv4-addr:value = '185.156.177.34']",
    "pattern_type": "stix",
    "confidence": 80
}
```
