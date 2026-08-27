import ipaddress
import logging
from fastapi import APIRouter, HTTPException, Path
from typing import Dict, Any
from services.threat_intel import threat_intel_service

logger = logging.getLogger("api.threat_intel")
router = APIRouter(prefix="/api/v1/enrich", tags=["Enrichment"])


@router.get("/ip/{ip}", response_model=Dict[str, Any])
async def enrich_ip_endpoint(
    ip: str = Path(..., min_length=1, max_length=50, description="IP address to enrich")
):
    """
    Async endpoint to enrich an IP address with external threat intelligence.
    """
    ip_clean = ip.strip()
    try:
        ipaddress.ip_address(ip_clean)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address format: {ip}")

    try:
        enrichment_data = await threat_intel_service.enrich_ip(ip_clean)
        return enrichment_data
    except Exception as e:
        logger.error(f"Enrichment endpoint failed for {ip_clean}: {e}")
        raise HTTPException(
            status_code=500, detail="Enrichment service encountered an internal error."
        )
