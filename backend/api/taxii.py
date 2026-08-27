"""
backend/api/taxii.py
-------------------------
PhantomNet TAXII 2.1 Feed Server — REST API Endpoints

Provides TAXII 2.1 protocol compliant endpoints:
  GET /taxii2/                                           — Server Discovery
  GET /taxii2/phantomnet/                                — API Root Information
  GET /taxii2/phantomnet/collections/                  — Collections List
  GET /taxii2/phantomnet/collections/{collection_id}/   — Specific Collection Detail
  GET /taxii2/phantomnet/collections/{collection_id}/objects/ — STIX Objects Retrieval

Query Parameter Filtering:
  - ?added_after=<ISO 8601 timestamp>  — Filter objects by creation date (strict >)

Spec Compliance:
  - Enforces OASIS TAXII 2.1 media type negotiation (Content-Type: application/taxii+json;version=2.1 and application/stix+json;version=2.1)
  - Rejects unsupported explicit Accept headers with 406 Not Acceptable
  - Queries SQLite database for dynamic collection mappings (tactics, honeypot sources) and builds STIX 2.1 bundles.

Week 18, Day 1 & Day 2 — TAXII Server Architecture & Collections Endpoint
Week 18, Day 4 — Add Filtering to TAXII Objects Endpoint (added_after)
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Response
# pyrefly: ignore [missing-import]
from fastapi.responses import JSONResponse
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import User
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from middleware.auth import decode_token, verify_password
# pyrefly: ignore [missing-import]
from sentinel.models import SentinelPlaybook
from schemas.taxii import (
    TaxiiApiRootResponse,
    TaxiiCollectionResource,
    TaxiiCollectionsResponse,
    TaxiiDiscoveryResponse,
    TaxiiEnvelopeResponse,
    TaxiiErrorResponse,
)

# pyrefly: ignore [missing-import]
from starlette.middleware.base import BaseHTTPMiddleware
# pyrefly: ignore [missing-import]
from starlette.requests import Request

logger = logging.getLogger("api.taxii")

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1 Feed"])

basic_auth = HTTPBasic(auto_error=False)
bearer_auth = HTTPBearer(auto_error=False)

def get_taxii_user(
    basic: Optional[HTTPBasicCredentials] = Depends(basic_auth),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_auth),
    db: Session = Depends(get_db)
) -> User:
    if bearer:
        token_data = decode_token(bearer.credentials)
        if token_data:
            user = db.query(User).filter(User.username == token_data.get("sub")).first()
            if user and user.status == "active":
                return user
    if basic:
        user = db.query(User).filter(User.username == basic.username).first()
        if user and user.status == "active" and verify_password(basic.password, user.hashed_password):
            return user
            
    err = TaxiiErrorResponse(
        title="Unauthorized",
        description="Invalid or missing authentication credentials.",
        http_status="401",
    )
    raise HTTPException(status_code=401, detail=err.model_dump())


def check_taxii_headers(
    accept: Optional[str] = None,
    content_type: Optional[str] = None,
    is_objects_endpoint: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Validate incoming request Accept and Content-Type headers per TAXII 2.1 specification.

    Returns:
        Dict representing TaxiiErrorResponse if validation fails, or None if valid.
    """
    # 1. Inspect Content-Type header if present in request
    if content_type and content_type.strip():
        ct_clean = content_type.strip().lower()
        valid_ct_patterns = [
            "application/taxii+json",
            "application/stix+json",
            "application/json",
        ]
        has_valid_ct = any(pat in ct_clean for pat in valid_ct_patterns)

        # Check explicit version requirement in Content-Type if specified
        if "version=" in ct_clean and "version=2.1" not in ct_clean:
            has_valid_ct = False

        if not has_valid_ct:
            err = TaxiiErrorResponse(
                title="Not Acceptable",
                description=(
                    f"The Content-Type header '{content_type}' is not supported by TAXII 2.1. "
                    f"Expected '{TAXII_MEDIA_TYPE}' or '{STIX_MEDIA_TYPE}'."
                ),
                http_status="406",
            )
            return err.model_dump()

    # 2. Inspect Accept header if present in request
    if not accept or not accept.strip():
        return None

    parts = [p.strip().lower() for p in accept.split(",")]

    # Check for wildcards
    if any(p == "*/*" or p == "application/*" for p in parts):
        return None

    valid_base_patterns = [
        "application/taxii+json",
        "application/stix+json",
        "application/json",
    ]

    has_acceptable_media = False
    for part in parts:
        # Must match a valid base media type
        if not any(base in part for base in valid_base_patterns):
            continue

        # If metadata endpoint and part ONLY specifies application/stix+json, reject
        if not is_objects_endpoint and "application/stix+json" in part and "application/taxii+json" not in part and "application/json" not in part:
            continue

        # If explicit version parameter is specified, it MUST be version=2.1
        if "version=" in part and "version=2.1" not in part:
            continue

        has_acceptable_media = True
        break

    if not has_acceptable_media:
        expected = STIX_MEDIA_TYPE if is_objects_endpoint else TAXII_MEDIA_TYPE
        err = TaxiiErrorResponse(
            title="Not Acceptable",
            description=(
                f"The requested Accept header '{accept}' is not supported by TAXII 2.1. "
                f"Expected '{expected}'."
            ),
            http_status="406",
        )
        return err.model_dump()

    return None


def validate_taxii_headers(
    accept: Optional[str] = None,
    content_type: Optional[str] = None,
    is_objects_endpoint: bool = False,
) -> Optional[JSONResponse]:
    """
    Validation helper to be invoked directly inside TAXII endpoint route handlers.
    Raises HTTP 406 or returns JSONResponse with 406 status on header negotiation failure.
    """
    err_dict = check_taxii_headers(accept, content_type, is_objects_endpoint=is_objects_endpoint)
    if err_dict:
        return JSONResponse(
            content=err_dict,
            status_code=406,
            headers={"Content-Type": TAXII_MEDIA_TYPE},
        )
    return None


def _validate_accept_header(accept: Optional[str]) -> None:
    """Legacy helper maintained for backward compatibility."""
    err_dict = check_taxii_headers(accept, is_objects_endpoint=False)
    if err_dict:
        raise HTTPException(
            status_code=406,
            detail=err_dict,
        )


class TaxiiContentNegotiationMiddleware(BaseHTTPMiddleware):
    """
    FastAPI Middleware enforcing strict TAXII 2.1 Content-Type header negotiation
    on all requests routed to /taxii2/ prefix.
    """

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/taxii2"):
            accept = request.headers.get("accept")
            content_type = request.headers.get("content-type")
            is_objects = "/objects" in request.url.path

            err_dict = check_taxii_headers(accept, content_type, is_objects_endpoint=is_objects)
            if err_dict:
                return JSONResponse(
                    content=err_dict,
                    status_code=406,
                    headers={"Content-Type": TAXII_MEDIA_TYPE},
                )

            response = await call_next(request)

            # Ensure proper Content-Type response header is set
            if is_objects:
                if accept and "application/taxii+json" in accept.lower() and "application/stix+json" not in accept.lower():
                    expected_ct = TAXII_MEDIA_TYPE
                else:
                    expected_ct = STIX_MEDIA_TYPE
            else:
                expected_ct = TAXII_MEDIA_TYPE

            if response.status_code < 400:
                response.headers["Content-Type"] = expected_ct
            else:
                if "content-type" not in response.headers or response.headers["content-type"] == "application/json":
                    response.headers["Content-Type"] = TAXII_MEDIA_TYPE

            return response

        return await call_next(request)


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
            media_types=[STIX_MEDIA_TYPE],
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
                            media_types=[STIX_MEDIA_TYPE],
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
                            media_types=[STIX_MEDIA_TYPE],
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
def taxii_discovery(
    accept: Optional[str] = Header(None),
    content_type: Optional[str] = Header(None),
    current_user: User = Depends(get_taxii_user),
) -> JSONResponse:
    err_resp = validate_taxii_headers(accept, content_type, is_objects_endpoint=False)
    if err_resp:
        return err_resp
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
def taxii_api_root(
    accept: Optional[str] = Header(None),
    content_type: Optional[str] = Header(None),
    current_user: User = Depends(get_taxii_user),
) -> JSONResponse:
    err_resp = validate_taxii_headers(accept, content_type, is_objects_endpoint=False)
    if err_resp:
        return err_resp
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
    content_type: Optional[str] = Header(None),
    current_user: User = Depends(get_taxii_user),
) -> JSONResponse:
    err_resp = validate_taxii_headers(accept, content_type, is_objects_endpoint=False)
    if err_resp:
        return err_resp
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
    content_type: Optional[str] = Header(None),
    current_user: User = Depends(get_taxii_user),
) -> JSONResponse:
    err_resp = validate_taxii_headers(accept, content_type, is_objects_endpoint=False)
    if err_resp:
        return err_resp
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


# ---------------------------------------------------------------------------
# 5. Timestamp Parsing Helper for added_after Filtering
# ---------------------------------------------------------------------------

def parse_added_after(
    added_after: Optional[str],
) -> tuple[Optional[datetime], Optional[JSONResponse]]:
    """
    Parse and validate an ISO 8601 / RFC 3339 timestamp string from the
    ``added_after`` query parameter.

    Supports formats:
      - Full datetime with Z suffix:     2026-07-01T00:00:00Z
      - Full datetime with offset:       2026-07-01T00:00:00+05:30
      - Full datetime without timezone:  2026-07-01T00:00:00 (treated as UTC)
      - Date only:                       2026-07-01 (treated as midnight UTC)
      - Microsecond precision:           2026-07-01T12:30:00.123456Z

    Args:
        added_after: Raw query parameter value, may be None or empty string.

    Returns:
        Tuple of (parsed_datetime, error_response).
        On success: (datetime, None)  — datetime is always UTC-aware.
        On skip:    (None, None)      — parameter was absent or empty.
        On error:   (None, JSONResponse) — 400 response with TAXII error body.
    """
    if not added_after or not added_after.strip():
        return None, None

    raw = added_after.strip()

    try:
        # Replace trailing 'Z' with '+00:00' for fromisoformat compatibility
        normalized = raw
        if normalized.upper().endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        dt = datetime.fromisoformat(normalized)

        # If the parsed datetime is naive (no timezone info), assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        # Normalize to UTC for consistent DB comparison
        dt = dt.astimezone(timezone.utc)

        return dt, None

    except (ValueError, TypeError) as exc:
        logger.warning("Invalid added_after timestamp '%s': %s", raw, exc)
        err = TaxiiErrorResponse(
            title="Invalid Timestamp",
            description=(
                f"The 'added_after' parameter value '{raw}' is not a valid "
                f"ISO 8601 / RFC 3339 timestamp. "
                f"Expected format: YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS±HH:MM"
            ),
            http_status="400",
        )
        return None, JSONResponse(
            content=err.model_dump(),
            status_code=400,
            headers={"Content-Type": TAXII_MEDIA_TYPE},
        )


# ---------------------------------------------------------------------------
# 6. GET /taxii2/phantomnet/collections/{id}/objects/ — Collection Objects Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/phantomnet/collections/{id}/objects/",
    response_model=TaxiiEnvelopeResponse,
    summary="Get TAXII Collection STIX Objects",
    description="Returns a STIX 2.1 bundle containing objects for the requested collection.",
)
@router.get(
    "/phantomnet/collections/{id}/objects",
    response_model=TaxiiEnvelopeResponse,
    include_in_schema=False,
)
def get_collection_objects(
    id: str = Path(..., description="The ID or alias of the collection"),
    added_after: Optional[str] = Query(
        None,
        description=(
            "ISO 8601 / RFC 3339 timestamp. Only objects with a created_at "
            "date strictly after this value will be returned. "
            "Example: 2026-07-01T00:00:00Z"
        ),
    ),
    limit: Optional[int] = Query(
        None,
        ge=1,
        le=1000,
        description="Maximum number of STIX objects to return. Max is 1000.",
    ),
    next_token: Optional[int] = Query(
        None,
        alias="next",
        description="Pagination offset index to fetch the next page of results.",
    ),
    db: Session = Depends(get_db),
    accept: Optional[str] = Header(None),
    content_type: Optional[str] = Header(None),
    current_user: User = Depends(get_taxii_user),
) -> JSONResponse:
    """
    Retrieve STIX 2.1 objects from a specific TAXII collection.
    
    Supports pagination via `limit` and `next` tokens, and time-based filtering 
    using the `added_after` query parameter.
    
    Returns a TAXII envelope containing the STIX objects.
    """
    err_resp = validate_taxii_headers(accept, content_type, is_objects_endpoint=True)
    if err_resp:
        return err_resp

    if not id or id.strip() == "":
        err = TaxiiErrorResponse(
            title="Invalid Parameter",
            description="Collection ID cannot be empty.",
            http_status="400",
        )
        return JSONResponse(
            content=err.model_dump(),
            status_code=400,
            headers={"Content-Type": TAXII_MEDIA_TYPE},
        )

    # Check if collection exists
    cols = get_taxii_collections(db)
    matched_col = next(
        (c for c in cols if c.id == id or c.alias == id), None
    )

    # Parse and validate added_after filter parameter
    added_after_dt, added_after_err = parse_added_after(added_after)
    if added_after_err:
        return added_after_err

    # Fetch playbooks from DB
    try:
        query = db.query(SentinelPlaybook)

        # Apply added_after timestamp filter (strict greater-than per TAXII 2.1 §5.4)
        if added_after_dt is not None:
            # Strip timezone info for comparison with naive DB timestamps
            filter_dt = added_after_dt.replace(tzinfo=None)
            query = query.filter(SentinelPlaybook.created_at > filter_dt)

        if matched_col and matched_col.id.startswith("tactic-"):
            # pyrefly: ignore [missing-import]
            from sqlalchemy import func
            tactic_slug = matched_col.id.replace("tactic-", "")
            query = query.filter(SentinelPlaybook.tactic.isnot(None))
            query = query.filter(
                func.lower(func.replace(func.replace(SentinelPlaybook.tactic, ' ', '-'), '/', '-')) == tactic_slug
            )
        elif matched_col and matched_col.id.startswith("honeypot-"):
            port_map = {"cowrie-ssh": 22, "web-http": 80, "web-https": 443, "dionaea-mysql": 3306, "dionaea-ftp": 21}
            port = port_map.get(matched_col.alias)
            if port:
                query = query.filter(SentinelPlaybook.dst_port == port)

        # Order by created_at to ensure consistent pagination
        query = query.order_by(SentinelPlaybook.created_at.asc())

        if next_token is not None:
            query = query.offset(next_token)

        # If a limit is provided, we fetch one extra to determine if there are more results
        safe_limit = limit if limit is not None else 100
        
        playbooks = query.limit(safe_limit + 1).all()
        
        more_results = len(playbooks) > safe_limit
        if more_results:
            playbooks = playbooks[:safe_limit]
            


    except Exception as e:
        logger.error("Failed to query playbooks for collection objects: %s", e)
        err = TaxiiErrorResponse(
            title="Internal Server Error",
            description=str(e),
            http_status="500",
        )
        return JSONResponse(
            content=err.model_dump(),
            status_code=500,
            headers={"Content-Type": TAXII_MEDIA_TYPE},
        )

    stix_objects: List[Dict[str, Any]] = []
    
    if playbooks:
        # 1. Base PhantomNet Identity Anchor Object
        phantomnet_identity = {
            "type": "identity",
            "id": "identity--0b784a91-4e78-5777-a721-6ffab3b2f211",
            "spec_version": "2.1",
            "name": "PhantomNet Threat Intelligence Feed",
            "identity_class": "system",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
        }
        stix_objects.append(phantomnet_identity)

    for pb in playbooks:
        created_at = (
            pb.created_at.isoformat() + "Z"
            if getattr(pb, "created_at", None)
            else datetime.utcnow().isoformat() + "Z"
        )
        updated_at = (
            pb.updated_at.isoformat() + "Z"
            if getattr(pb, "updated_at", None)
            else created_at
        )

        pb_seed = str(pb.playbook_id) if getattr(pb, "playbook_id", None) else str(uuid.uuid4())
        
        # Ensure valid STIX 2.1 UUID format for Report ID
        if pb_seed.startswith("report--"):
            report_id = pb_seed
        else:
            report_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"phantomnet:report:{pb_seed}"))
            report_id = f"report--{report_uuid}"

        object_refs: List[str] = [phantomnet_identity["id"]]

        # Optional AttackPattern Object
        if getattr(pb, "technique_id", None):
            t_id = pb.technique_id.strip()
            ap_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"phantomnet:attack-pattern:{t_id}"))
            ap_id = f"attack-pattern--{ap_uuid}"
            ap_obj = {
                "type": "attack-pattern",
                "id": ap_id,
                "spec_version": "2.1",
                "name": getattr(pb, "technique_name", None) or t_id,
                "description": f"MITRE ATT&CK technique {t_id} associated with tactic {getattr(pb, 'tactic', 'Unknown')}",
                "created": created_at,
                "modified": updated_at,
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": t_id,
                    "url": getattr(pb, "mitre_url", None) or f"https://attack.mitre.org/techniques/{t_id.replace('.', '/')}/"
                }]
            }
            stix_objects.append(ap_obj)
            object_refs.append(ap_id)

        # Optional Indicator Object
        if getattr(pb, "src_ip", None):
            ind_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"phantomnet:indicator:{pb_seed}:{pb.src_ip}"))
            indicator_id = f"indicator--{ind_uuid}"
            indicator_obj = {
                "type": "indicator",
                "id": indicator_id,
                "spec_version": "2.1",
                "name": f"Malicious Source IP: {pb.src_ip}",
                "pattern": f"[ipv4-addr:value = '{pb.src_ip}']",
                "pattern_type": "stix",
                "valid_from": created_at,
                "created": created_at,
                "modified": updated_at,
            }
            stix_objects.append(indicator_obj)
            object_refs.append(indicator_id)

        # Report Object
        report_obj: Dict[str, Any] = {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "name": getattr(pb, "playbook_name", None) or f"Sentinel Threat Playbook ({pb_seed})",
            "description": getattr(pb, "playbook_content", None) or getattr(pb, "llm_narrative", None) or f"Threat detection playbook for tactic {getattr(pb, 'tactic', 'Unknown')}",
            "published": created_at,
            "created": created_at,
            "modified": updated_at,
            "object_refs": object_refs,
        }
        stix_objects.append(report_obj)

    res_ct = STIX_MEDIA_TYPE
    if accept and "application/taxii+json" in accept.lower() and "application/stix+json" not in accept.lower():
        res_ct = TAXII_MEDIA_TYPE

    if res_ct == TAXII_MEDIA_TYPE:
        next_token_out = (next_token or 0) + safe_limit if more_results else None
        response_content = {
            "more": more_results,
            "next": str(next_token_out) if next_token_out is not None else None,
            "objects": stix_objects,
        }
        # Filter out None values
        response_content = {k: v for k, v in response_content.items() if v is not None}
    else:
        response_content = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects,
        }

    return JSONResponse(
        content=response_content,
        status_code=200,
        headers={"Content-Type": res_ct},
    )
