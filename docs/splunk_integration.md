# Splunk Integration Guide

This document outlines how to integrate the PhantomNet Active Defense Platform with Splunk using the Splunk HTTP Event Collector (HEC).

## Overview
PhantomNet includes a Universal SIEM Exporter that can route events to ELK, Syslog, CEF endpoints, or Splunk. When configured for Splunk, it leverages a high-performance batching HEC client that maps PhantomNet events (like `PacketLog` and `Alert`) into Splunk's native JSON format.

## Prerequisites
- A running instance of Splunk Enterprise or Splunk Cloud.
- HTTP Event Collector (HEC) enabled in Splunk.
- A generated HEC Token.

## Configuration
To enable the Splunk Exporter, you must configure the following environment variables in your PhantomNet deployment (`.env` file or environment):

```bash
# Enable Splunk export
SIEM_TYPE=splunk

# Splunk HEC Endpoint URL
# Note: Ensure you include the exact path to /services/collector/event
SPLUNK_HEC_URL=https://<your-splunk-instance>:8088/services/collector/event

# Splunk HEC Token
SPLUNK_HEC_TOKEN=your-generated-hec-token-here

# Optional Batch Delivery Settings (default values shown below)
SIEM_BATCH_SIZE=1000
SIEM_EXPORT_INTERVAL=60
```

## How It Works
1. **Background Service**: The `SIEMExporterService` runs independently within the PhantomNet backend, waking up every `SIEM_EXPORT_INTERVAL` seconds.
2. **Batching**: It queries for new `PacketLogs` and `Alerts` that have not yet been exported, batching them into chunks of size `SIEM_BATCH_SIZE`.
3. **Data Transformation**: The logs are transformed into Splunk-compatible dictionaries. The exporter explicitly overrides the metadata:
   - `source="phantomnet_honeypot"`
   - `sourcetype="phantomnet:event"`
4. **Resilience**: The client sends data to the Splunk HEC endpoint using a configured `requests.Session` for connection pooling. If delivery fails (e.g., Splunk restarts), the service will retry with exponential backoff.

## Recommended Splunk Setup

### 1. Enable HEC
Navigate to **Settings** > **Data Inputs** > **HTTP Event Collector** and ensure it is globally enabled.

### 2. Create the HEC Token
Create a new token named `PhantomNet_HEC`.
- **Source type**: Leave as Automatic, or optionally pre-define `phantomnet:event`.
- **App context**: Search & Reporting (or a dedicated PhantomNet App).
- **Index**: Select a specific index for these logs (e.g., `main` or a new index `phantomnet_sec`). Note: By default, the exporter relies on the token's default index configuration in Splunk.

### 3. Verify Connectivity
You can manually test connecting to Splunk HEC from the PhantomNet server line using `curl`:

```bash
curl -k  https://<splunk-host>:8088/services/collector/event \
  -H "Authorization: Splunk <your-hec-token>" \
  -d '{"event": "Test Event from PhantomNet", "sourcetype": "phantomnet:event"}'
```
You should receive `{"text":"Success","code":0}`.

## Field Mappings
PhantomNet events mapped to Splunk HEC schema:

| Splunk Metacontext | PhantomNet Value |
|--------------------|------------------|
| `time` | Extract from `PacketLog.timestamp` or `Alert.timestamp` in Epoch seconds |
| `host` | `phantomnet_ids` |
| `source` | `phantomnet_honeypot` |
| `sourcetype` | `phantomnet:event` |
| `event` | The JSON-serialized contents of the log entry |

Because data is transported as serialized JSON objects, Splunk's automatic field extraction (KV extraction) will easily parse out properties such as `src_ip`, `threat_score`, `attack_type`, and others natively.
