# TAXII Feed Pagination Test Report and Performance Metrics

## Test Configuration
- **Endpoint**: `GET /taxii2/phantomnet/collections/{id}/objects/`
- **Collection**: `honeypot-cowrie-ssh`
- **Total Seeded Records**: 550
- **Pagination Limit**: 100

## Performance Metrics
| Offset | Limit | Playbooks Returned | Total STIX Objects | Response Time (ms) |
|--------|-------|--------------------|--------------------|--------------------|
| 0 | 100 | 100 | 301 | 32.27 |
| 100 | 100 | 100 | 301 | 12.03 |
| 200 | 100 | 100 | 301 | 9.33 |
| 300 | 100 | 100 | 301 | 10.41 |
| 400 | 100 | 100 | 301 | 9.86 |
| 500 | 100 | 50 | 151 | 9.05 |

**Average Response Time**: 13.83 ms

## Verification Results
- ✅ Database successfully seeded with 550 STIX bundle records.
- ✅ Pagination logic verified: `limit` and `next` tokens properly split results into pages.
- ✅ Response times measured successfully.
- ✅ Expected counts per page exactly match results.
