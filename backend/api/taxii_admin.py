"""
TAXII Client Administration API for PhantomNet (Phase 1).

Allows Administrators to issue, list, and revoke Machine-to-Machine (M2M) credentials
for external threat intelligence platforms ingesting PhantomNet's TAXII 2.1 STIX feeds.
"""

import json
import logging
import secrets
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import TaxiiClient, User
from middleware.auth import hash_password, require_role
from services.audit_service import audit_log

logger = logging.getLogger("api.taxii_admin")
router = APIRouter(prefix="/api/v1/admin/taxii", tags=["Admin — TAXII Clients"])


# ---- Pydantic Schemas ----


class TaxiiClientCreate(BaseModel):
    client_name: str = Field(..., min_length=2, max_length=100)
    scopes: List[str] = Field(default=["taxii:read", "taxii:collections:read"])
    allowed_collections: Optional[List[str]] = None


class TaxiiClientCreatedResponse(BaseModel):
    client_name: str
    key_id: str
    secret: str  # Displayed only once upon creation
    scopes: List[str]
    allowed_collections: Optional[List[str]]
    created_at: str


class TaxiiClientResponse(BaseModel):
    id: int
    client_name: str
    key_id: str
    scopes: List[str]
    allowed_collections: Optional[List[str]]
    last_used_at: Optional[str]
    revoked_at: Optional[str]
    created_at: str


# ---- Endpoints ----


@router.post("/clients", response_model=TaxiiClientCreatedResponse)
def create_taxii_client(
    req: TaxiiClientCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("Admin")),
):
    """Generate new machine-to-machine credentials for a TAXII feed consumer."""
    existing = db.query(TaxiiClient).filter(TaxiiClient.client_name == req.client_name).first()
    if existing and not existing.revoked_at:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"TAXII client with name '{req.client_name}' already exists",
        )

    key_id = f"taxii_{secrets.token_hex(8)}"
    raw_secret = secrets.token_urlsafe(32)
    secret_hash = hash_password(raw_secret)

    client = TaxiiClient(
        client_name=req.client_name,
        key_id=key_id,
        secret_hash=secret_hash,
        scopes=json.dumps(req.scopes),
        allowed_collections=json.dumps(req.allowed_collections) if req.allowed_collections else None,
        created_at=datetime.utcnow(),
    )
    db.add(client)
    db.commit()
    db.refresh(client)

    audit_log(
        actor=admin.username,
        action="TAXII_CLIENT_CREATE",
        result="success",
        target=req.client_name,
        details={"key_id": key_id, "scopes": req.scopes},
        db=db,
    )

    return TaxiiClientCreatedResponse(
        client_name=client.client_name,
        key_id=client.key_id,
        secret=raw_secret,
        scopes=req.scopes,
        allowed_collections=req.allowed_collections,
        created_at=client.created_at.isoformat(),
    )


@router.get("/clients", response_model=List[TaxiiClientResponse])
def list_taxii_clients(
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("Admin")),
):
    """List all registered TAXII client consumers (secrets are never exposed)."""
    clients = db.query(TaxiiClient).order_by(TaxiiClient.created_at.desc()).all()
    results = []
    for c in clients:
        scopes = json.loads(c.scopes) if c.scopes else []
        collections = json.loads(c.allowed_collections) if c.allowed_collections else None
        results.append(
            TaxiiClientResponse(
                id=c.id,
                client_name=c.client_name,
                key_id=c.key_id,
                scopes=scopes,
                allowed_collections=collections,
                last_used_at=c.last_used_at.isoformat() if c.last_used_at else None,
                revoked_at=c.revoked_at.isoformat() if c.revoked_at else None,
                created_at=c.created_at.isoformat() if c.created_at else None,
            )
        )
    return results


@router.delete("/clients/{key_id}")
def revoke_taxii_client(
    key_id: str = Path(..., min_length=5, max_length=50),
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("Admin")),
):
    """Revoke a TAXII client's credentials immediately."""
    client = db.query(TaxiiClient).filter(TaxiiClient.key_id == key_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="TAXII client not found")

    client.revoked_at = datetime.utcnow()
    db.commit()

    audit_log(
        actor=admin.username,
        action="TAXII_CLIENT_REVOKE",
        result="success",
        target=client.client_name,
        details={"key_id": key_id},
        db=db,
    )

    return {"status": "success", "message": f"TAXII client '{client.client_name}' revoked"}
