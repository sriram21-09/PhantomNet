from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from services.threat_intel import threat_intel_service
import logging

logger = logging.getLogger("api_threat_intel")
router = APIRouter(prefix="/api/v1/enrich", tags=["Enrichment"])

@router.get("/ip/{ip}", response_model=Dict[str, Any])
async def enrich_ip_endpoint(ip: str):
    """
    Async endpoint to enrich an IP address with external threat intelligence.
    """
    try:
        enrichment_data = await threat_intel_service.enrich_ip(ip)
        return enrichment_data
    except Exception as e:
        logger.error(f"Enrichment endpoint failed for {ip}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Enrichment service encountered an internal error."
        )
