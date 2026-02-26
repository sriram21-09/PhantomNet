import pytest
import pytest_asyncio
import httpx
from unittest.mock import patch, AsyncMock, MagicMock
from services.threat_intel import ThreatIntelService

@pytest_asyncio.fixture
async def intel_service():
    with patch.dict('os.environ', {'ABUSE_IPDB_KEY': 'test_key', 'ALIENVAULT_OTX_KEY': 'test_otx'}):
        service = ThreatIntelService()
        yield service
        await service.close()

@pytest.mark.asyncio
async def test_enrich_internal_ip(intel_service):
    """Internal IPs should return early with a trusted status."""
    result = await intel_service.enrich_ip("127.0.0.1")
    assert result["status"] == "trusted"
    assert "local" in result["source"]

@pytest.mark.asyncio
async def test_fetch_abuse_ipdb_success(intel_service):
    """Test successful AbuseIPDB enrichment."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 85,
            "totalReports": 10,
            "lastReportedAt": "2026-02-21T10:00:00Z",
            "domain": "malicious.com",
            "usageType": "Data Center",
            "isWhitelisted": False
        }
    }
    
    with patch.object(intel_service.client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await intel_service._fetch_abuse_ipdb("8.8.8.8")
        
    assert result["abuse_confidence_score"] == 85
    assert result["total_reports"] == 10
    assert result["domain"] == "malicious.com"

@pytest.mark.asyncio
async def test_fetch_alienvault_otx_success(intel_service):
    """Test successful AlienVault OTX enrichment."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": {"count": 5},
        "reputation": 10,
        "last_seen": "2026-02-21T11:00:00Z",
        "tags": ["malware"]
    }
    
    with patch.object(intel_service.client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await intel_service._fetch_alienvault_otx("8.8.8.8")
        
    assert result["pulse_count"] == 5
    assert result["reputation"] == 10
