from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

@router.get("/taxii2/", summary="TAXII 2.1 Discovery")
async def taxii_discovery():
    """
    Returns the TAXII 2.1 discovery document containing system-wide api_roots.
    """
    discovery_data = {
        "title": "PhantomNet TAXII 2.1 Server",
        "description": "System-wide TAXII 2.1 discovery document",
        "contact": "admin@phantomnet.local",
        "default": "https://phantomnet.local/taxii2/api1/",
        "api_roots": [
            "https://phantomnet.local/taxii2/api1/"
        ]
    }
    return JSONResponse(
        content=discovery_data,
        media_type="application/taxii+json;version=2.1"
    )
