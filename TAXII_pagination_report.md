# TAXII Feed Pagination Test Report and Performance Metrics

## Test Configuration
- **Endpoint**: `GET /taxii2/phantomnet/collections/{id}/objects/`
- **Collection**: `honeypot-cowrie-ssh`
- **Total Seeded Records**: 550
- **Pagination Limit**: 100

## Performance Metrics
| Offset | Limit | Playbooks Returned | Total STIX Objects | Response Time (ms) |
|--------|-------|--------------------|--------------------|--------------------|
| 0 | 100 | 100 | 301 | 90.45 |
| 100 | 100 | 100 | 301 | 29.63 |
| 200 | 100 | 100 | 301 | 29.49 |
| 300 | 100 | 100 | 301 | 31.82 |
| 400 | 100 | 100 | 301 | 30.70 |
| 500 | 100 | 50 | 151 | 24.91 |

**Average Response Time**: 39.50 ms

## Verification Results
- ✅ Database successfully seeded with 550 STIX bundle records.
- ✅ Pagination logic verified: `limit` and `next` tokens properly split results into pages.
- ✅ Response times measured successfully.
- ✅ Expected counts per page exactly match results.
