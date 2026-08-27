from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
import os
from typing import List
from pydantic import BaseModel
from database.models import HoneypotNode, Policy
from services.node_manager import NodeManager
from services.policy_engine import PolicyEngine

import hmac
import ipaddress
import re
from pydantic import BaseModel, Field, field_validator

from database.database import get_db

router = APIRouter(prefix="/api/v1/management", tags=["Management"])

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


def get_api_key(api_key: str = Security(api_key_header)):
    if not api_key:
        raise HTTPException(
            status_code=401, detail="Missing API Key header (X-API-Key)"
        )
    expected_key = os.getenv("API_KEY", "default_key")
    if not hmac.compare_digest(api_key.encode("utf-8"), expected_key.encode("utf-8")):
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key


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
    api_key: str = Depends(get_api_key),
):
    manager = NodeManager(db)
    node = manager.register_node(req.hostname, req.ip_address, req.honeypot_type)
    return {"status": "success", "node_id": node.node_id}


@router.post("/heartbeat")
def node_heartbeat(
    req: NodeHeartbeatRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key),
):
    manager = NodeManager(db)
    if manager.update_heartbeat(req.node_id):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Node not found")


@router.get("/nodes")
def list_nodes(db: Session = Depends(get_db), api_key: str = Depends(get_api_key)):
    manager = NodeManager(db)
    return manager.list_nodes()


@router.get("/policies")
def list_policies(db: Session = Depends(get_db), api_key: str = Depends(get_api_key)):
    engine = PolicyEngine(db)
    return engine.list_policies()


@router.post("/policies")
def create_policy(
    req: PolicyCreateRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key),
):
    engine = PolicyEngine(db)
    policy = engine.create_policy(req.name, req.description, req.config)
    return {"status": "success", "policy_id": policy.id}


@router.post("/policies/assign")
def assign_policy(
    req: PolicyAssignRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key),
):
    engine = PolicyEngine(db)
    if engine.assign_policy_to_node(req.node_id, req.policy_id):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Node or Policy not found")
