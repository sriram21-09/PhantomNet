"""
backend/api/taxii.py
-------------------------
PhantomNet TAXII 2.1 Feed Server — REST API Endpoints

Provides TAXII 2.1 protocol compliant endpoints:
  GET /taxii2/                                      — Server Discovery
  GET /taxii2/phantomnet/                           — API Root Information
  GET /taxii2/phantomnet/collections/             — Collections List
  GET /taxii2/phantomnet/collections/{id}/          — Specific Collection Detail

Spec Compliance:
  - Enforces OASIS TAXII 2.1 media type negotiation (Content-Type: application/taxii+json;version=2.1)
  - Rejects unsupported explicit Accept headers with 406 Not Acceptable
  - Queries SQLite database for dynamic collection mappings (tactics, honeypot sources)

Week 18, Day 1 & Day 2 — TAXII Server Architecture & Collections Endpoint
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from database.database import get_db
from sentinel.models import SentinelPlaybook
from schemas.taxii import (
    TaxiiApiRootResponse,
    TaxiiCollectionResource,
    TaxiiCollectionsResponse,
    TaxiiDiscoveryResponse,
    TaxiiErrorResponse,
)

logger = logging.getLogger("api.taxii")

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1 Feed"])


def _validate_accept_header(accept: Optional[str]) -> None:
    """
    Validate the client Accept header per TAXII 2.1 spec.
    If an explicit Accept header is provided that demands an unsupported format,
    raises HTTP 406 Not Acceptable.
    """
    if not accept:
        return

    valid_patterns = [
        "application/taxii+json",
        "application/stix+json",
        "application/json",
        "*/*",
        "application/*",
    ]

    parts = [p.strip().lower() for p in accept.split(",")]
    is_valid = any(
        any(pattern in part for pattern in valid_patterns)
        for part in parts
    )

    if not is_valid:
        err = TaxiiErrorResponse(
            title="Not Acceptable",
            description=(
                f"The requested Accept header '{accept}' is not supported by TAXII 2.1. "
                f"Expected '{TAXII_MEDIA_TYPE}' or 'application/stix+json;version=2.1'."
            ),
            http_status="406",
        )
        raise HTTPException(
            status_code=406,
            detail=err.model_dump(),
        )


def get_taxii_collections(db: Session) -> List[TaxiiCollectionResource]:
    """
    Query database to determine available collection mappings.
    Combines primary approved playbooks collection with dynamic collections
    derived from MITRE tactics and honeypot service ports in Sentinel playbooks.

    Args:
        db: SQLAlchemy database session.

    Returns:
        List of TaxiiCollectionResource models.
    """
    collections: List[TaxiiCollectionResource] = [
        TaxiiCollectionResource(
            id="sentinel-playbooks-approved",
            title="Approved Sentinel Playbooks",
            description="STIX 2.1 bundles generated from approved PhantomNet honeypot threat detections.",
            alias="approved-playbooks",
            can_read=True,
            can_write=False,
            media_types=["application/stix+json;version=2.1"],
        )
    ]

    # Dynamic collection mappings: group by MITRE ATT&CK tactic in DB
    try:
        tactics = (
            db.query(SentinelPlaybook.tactic)
            .filter(SentinelPlaybook.tactic.isnot(None))
            .distinct()
            .all()
        )
        for (tactic_name,) in tactics:
            if tactic_name and tactic_name.strip():
                slug = tactic_name.strip().lower().replace(" ", "-").replace("/", "-")
                col_id = f"tactic-{slug}"
                if not any(c.id == col_id for c in collections):
                    collections.append(
                        TaxiiCollectionResource(
                            id=col_id,
                            title=f"Collection: {tactic_name}",
                            description=f"Sentinel threat intelligence collection for MITRE ATT&CK tactic '{tactic_name}'.",
                            alias=slug,
                            can_read=True,
                            can_write=False,
                            media_types=["application/stix+json;version=2.1"],
                        )
                    )
    except Exception as exc:
        logger.warning("Failed to query tactic collections from DB: %s", exc)

    # Dynamic collection mappings: group by honeypot target port / service
    try:
        ports = (
            db.query(SentinelPlaybook.dst_port)
            .filter(SentinelPlaybook.dst_port.isnot(None))
            .distinct()
            .all()
        )
        port_service_map = {
            22: ("cowrie-ssh", "Cowrie SSH Honeypot Collection"),
            80: ("web-http", "Web HTTP Honeypot Collection"),
            443: ("web-https", "Web HTTPS Honeypot Collection"),
            3306: ("dionaea-mysql", "Dionaea MySQL Honeypot Collection"),
            21: ("dionaea-ftp", "Dionaea FTP Honeypot Collection"),
        }
        for (port,) in ports:
            if port in port_service_map:
                alias_name, title_name = port_service_map[port]
                col_id = f"honeypot-{alias_name}"
                if not any(c.id == col_id for c in collections):
                    collections.append(
                        TaxiiCollectionResource(
                            id=col_id,
                            title=title_name,
                            description=f"Threat intelligence gathered from honeypot service running on port {port}.",
                            alias=alias_name,
                            can_read=True,
                            can_write=False,
                            media_types=["application/stix+json;version=2.1"],
                        )
                    )
    except Exception as exc:
        logger.warning("Failed to query honeypot collections from DB: %s", exc)

    return collections


# ---------------------------------------------------------------------------
# 1. GET /taxii2/ — Server Discovery Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/",
    response_model=TaxiiDiscoveryResponse,
    summary="TAXII 2.1 Server Discovery",
    description="Returns TAXII 2.1 server discovery document listing hosted API root URLs.",
)
@router.get(
    "",
    response_model=TaxiiDiscoveryResponse,
    include_in_schema=False,
)
def taxii_discovery(accept: Optional[str] = Header(None)) -> JSONResponse:
    _validate_accept_header(accept)
    data = TaxiiDiscoveryResponse()
    return JSONResponse(
        content=data.model_dump(),
        status_code=200,
        headers={"Content-Type": TAXII_MEDIA_TYPE},
    )


# ---------------------------------------------------------------------------
# 2. GET /taxii2/phantomnet/ — API Root Information Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/phantomnet/",
    response_model=TaxiiApiRootResponse,
    summary="TAXII 2.1 API Root Information",
    description="Returns metadata and capabilities for the primary phantomnet API root.",
)
@router.get(
    "/phantomnet",
    response_model=TaxiiApiRootResponse,
    include_in_schema=False,
)
def taxii_api_root(accept: Optional[str] = Header(None)) -> JSONResponse:
    _validate_accept_header(accept)
    data = TaxiiApiRootResponse()
    return JSONResponse(
        content=data.model_dump(),
        status_code=200,
        headers={"Content-Type": TAXII_MEDIA_TYPE},
    )


# ---------------------------------------------------------------------------
# 3. GET /taxii2/phantomnet/collections/ — Collections List Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/phantomnet/collections/",
    response_model=TaxiiCollectionsResponse,
    summary="TAXII 2.1 Collections List",
    description="Returns list of STIX collection resources available under the phantomnet API root.",
)
@router.get(
    "/phantomnet/collections",
    response_model=TaxiiCollectionsResponse,
    include_in_schema=False,
)
def list_collections(
    db: Session = Depends(get_db),
    accept: Optional[str] = Header(None),
) -> JSONResponse:
    _validate_accept_header(accept)
    cols = get_taxii_collections(db)
    res = TaxiiCollectionsResponse(collections=cols)
    return JSONResponse(
        content=res.model_dump(),
        status_code=200,
        headers={"Content-Type": TAXII_MEDIA_TYPE},
    )


# ---------------------------------------------------------------------------
# 4. GET /taxii2/phantomnet/collections/{collection_id}/ — Collection Detail Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/phantomnet/collections/{collection_id}/",
    response_model=TaxiiCollectionResource,
    summary="TAXII 2.1 Collection Resource",
    description="Returns metadata for a specific collection identified by ID or alias.",
)
@router.get(
    "/phantomnet/collections/{collection_id}",
    response_model=TaxiiCollectionResource,
    include_in_schema=False,
)
def get_collection_detail(
    collection_id: str,
    db: Session = Depends(get_db),
    accept: Optional[str] = Header(None),
) -> JSONResponse:
    _validate_accept_header(accept)
    cols = get_taxii_collections(db)

    matched: Optional[TaxiiCollectionResource] = None
    for col in cols:
        if col.id == collection_id or col.alias == collection_id:
            matched = col
            break

    if not matched:
        err = TaxiiErrorResponse(
            title="Collection Not Found",
            description=f"Collection '{collection_id}' was not found on this TAXII server.",
            http_status="404",
        )
        return JSONResponse(
            content=err.model_dump(),
            status_code=404,
            headers={"Content-Type": TAXII_MEDIA_TYPE},
        )

    return JSONResponse(
        content=matched.model_dump(),
        status_code=200,
        headers={"Content-Type": TAXII_MEDIA_TYPE},
    )
