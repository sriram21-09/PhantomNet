# Live Threat Intelligence Enrichment

PhantomNet integrates with external threat intelligence providers to enrich network traffic data and improve the accuracy of its ML detection models.

## Supported Providers

### AbuseIPDB
- **Purpose**: Provides confidence scores based on community-sourced reports of malicious activity.
- **Data Points**: Abuse confidence score, total reports, last reported date, domain information.

### AlienVault OTX (Open Threat Exchange)
- **Purpose**: Monitors indicators of compromise (IoCs) and pulses from the global security community.
- **Data Points**: Pulse counts, reputation scores, tags, and classification.

## Configuration

To enable live enrichment, add the following environment variables to your `.env` file:

```env
ABUSE_IPDB_KEY=your_abuseipdb_api_key_here
ALIENVAULT_OTX_KEY=your_alienvault_otx_key_here
```

*Note: If keys are missing, the service will provide partial data or placeholders.*

## Implementation Details

### Backend Service
The `ThreatIntelService` in `backend/services/threat_intel.py` handles:
- **Asynchronous I/O**: Uses `httpx.AsyncClient` for non-blocking API calls.
- **Concurrent Execution**: Fetches data from multiple providers simultaneously using `asyncio.gather`.
- **In-memory Caching**: Efficiently caches results (1-hour TTL).
- **Integration**: Seamlessly integrated with the `ThreatAnalyzerService` background loop.

### ML Integration
Enrichment data is used to adjust ML threat scores. If an IP has high confidence of abuse (>50%) on AbuseIPDB, the threat score is boosted, potentially escalating the `threat_level` to `HIGH`.

### UI Component
The `ThreatIntelWidget.jsx` provides a professional visual representation of the enrichment data, including color-coded severity levels and key metrics.

## API Endpoint

`GET /api/v1/enrich/ip/{ip}`

Returns a JSON object containing merged enrichment data from all active providers.
