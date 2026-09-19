from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
import os
import hmac
import ipaddress
import re
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from database.models import HoneypotNode, Policy, User
from database.database import get_db
from middleware.auth import get_current_user
from services.node_manager import NodeManager
from services.policy_engine import PolicyEngine

router = APIRouter(prefix="/api/v1/management", tags=["Management"])

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


def require_management_auth(
    request: Request,
    api_key: Optional[str] = Security(api_key_header),
    db: Session = Depends(get_db),
):
    """Authenticate management requests via X-API-Key or Admin session token."""
    # 1. Check API Key
    if api_key:
        expected_key = os.getenv("API_KEY", "")
        if not expected_key or expected_key in ["default_key", "secret"]:
            if os.getenv("ENVIRONMENT", "local").lower() in ["production", "prod"]:
                raise HTTPException(
                    status_code=500, detail="Insecure or missing API_KEY configured in production"
                )
            expected_key = expected_key or "default_key"

        if hmac.compare_digest(api_key.encode("utf-8"), expected_key.encode("utf-8")):
            return "api_key"

    # 2. Check Admin user bearer token or cookie session
    try:
        auth_hdr = request.headers.get("authorization")
        cred = None
        if auth_hdr and auth_hdr.startswith("Bearer "):
            from fastapi.security import HTTPAuthorizationCredentials
            cred = HTTPAuthorizationCredentials(scheme="Bearer", credentials=auth_hdr[7:])
        
        # Check token directly
        from middleware.auth import decode_token
        raw_token = cred.credentials if cred else request.cookies.get("phantomnet_access_token")
        if raw_token:
            payload = decode_token(raw_token)
            if payload and payload.get("role") == "Admin":
                user = db.query(User).filter(User.username == payload.get("sub")).first()
                if user and user.status == "active":
                    return user.username
    except Exception:
        pass

    raise HTTPException(
        status_code=401,
        detail="Management endpoints require Admin role or valid X-API-Key header",
    )



class NodeRegisterRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: str = Field(..., min_length=1, max_length=45)
    honeypot_type: str = Field(..., min_length=1, max_length=50)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Hostname cannot be empty or whitespace")
        return v

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")
        return v


class NodeHeartbeatRequest(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., max_length=1000)
    config: dict


class PolicyAssignRequest(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=100)
    policy_id: int = Field(..., ge=1)


@router.post("/register")
def register_node(
    req: NodeRegisterRequest,
    db: Session = Depends(get_db),
    auth: str = Depends(require_management_auth),
):
    manager = NodeManager(db)
    node = manager.register_node(req.hostname, req.ip_address, req.honeypot_type)
    return {"status": "success", "node_id": node.node_id}


@router.post("/heartbeat")
def node_heartbeat(
    req: NodeHeartbeatRequest,
    db: Session = Depends(get_db),
    auth: str = Depends(require_management_auth),
):
    manager = NodeManager(db)
    if manager.update_heartbeat(req.node_id):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Node not found")


@router.get("/nodes")
def list_nodes(db: Session = Depends(get_db), auth: str = Depends(require_management_auth)):
    manager = NodeManager(db)
    return manager.list_nodes()


@router.get("/policies")
def list_policies(db: Session = Depends(get_db), auth: str = Depends(require_management_auth)):
    engine = PolicyEngine(db)
    return engine.list_policies()


@router.post("/policies")
def create_policy(
    req: PolicyCreateRequest,
    db: Session = Depends(get_db),
    auth: str = Depends(require_management_auth),
):
    engine = PolicyEngine(db)
    policy = engine.create_policy(req.name, req.description, req.config)
    return {"status": "success", "policy_id": policy.id}


@router.post("/policies/assign")
def assign_policy(
    req: PolicyAssignRequest,
    db: Session = Depends(get_db),
    auth: str = Depends(require_management_auth),
):
    engine = PolicyEngine(db)
    if engine.assign_policy_to_node(req.node_id, req.policy_id):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Node or Policy not found")
