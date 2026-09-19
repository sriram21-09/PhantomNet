"""
Ingestion Gateway API Router
Provides high-throughput, authenticated event ingestion endpoints for honeypots.
Explicitly isolated from database connections.
"""
import os
import json
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Request, Response, Header, HTTPException, status, Depends
from pydantic import ValidationError

from services.ingestion_gateway import (
    IngestionGateway,
    IngestionBackpressureError,
    IngestionAuthenticationError,
)

from middleware.auth import get_current_user
from database.models import User

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])

# Global singleton or dependency injectable instance
_gateway_instance: Optional[IngestionGateway] = None


def get_ingestion_gateway() -> IngestionGateway:
    global _gateway_instance
    if _gateway_instance is None:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        _gateway_instance = IngestionGateway(redis_url=redis_url)
    return _gateway_instance


def set_ingestion_gateway(gateway: IngestionGateway):
    """Allows test fixtures to inject mock/fake gateway instances."""
    global _gateway_instance
    _gateway_instance = gateway


@router.post(
    "/event",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a single honeypot event envelope",
)
async def ingest_event(
    request: Request,
    x_honeypot_signature: Optional[str] = Header(None, alias="X-Honeypot-Signature"),
    x_honeypot_timestamp: Optional[int] = Header(None, alias="X-Honeypot-Timestamp"),
    gateway: IngestionGateway = Depends(get_ingestion_gateway),
):
    body_bytes = await request.body()

    # Pre-parse Origin Authentication Verification
    # Anonymous requests without HMAC headers or embedded auth must be rejected with 401
    if not x_honeypot_signature or x_honeypot_timestamp is None:
        if not body_bytes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing required honeypot origin signature headers",
            )
        try:
            data = json.loads(body_bytes.decode("utf-8"))
            if not isinstance(data, dict) or "_origin_auth" not in data:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing required honeypot origin signature headers",
                )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing required honeypot origin signature headers",
            )
    else:
        try:
            data = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Malformed JSON body",
            )

    try:
        result = await gateway.ingest_event_async(
            event_data=data,
            raw_bytes=body_bytes,
            signature=x_honeypot_signature,
            timestamp=x_honeypot_timestamp,
        )
        return result
    except IngestionAuthenticationError as ae:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(ae))
    except IngestionBackpressureError as be:
        return Response(
            content=json.dumps({"detail": str(be), "retry_after": 5}),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json",
            headers={"Retry-After": "5"},
        )
    except ValidationError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=ve.errors())
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post(
    "/batch",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a batch of honeypot event envelopes",
)
async def ingest_batch(
    request: Request,
    x_honeypot_signature: Optional[str] = Header(None, alias="X-Honeypot-Signature"),
    x_honeypot_timestamp: Optional[int] = Header(None, alias="X-Honeypot-Timestamp"),
    gateway: IngestionGateway = Depends(get_ingestion_gateway),
):
    body_bytes = await request.body()
    if not x_honeypot_signature or x_honeypot_timestamp is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required honeypot origin signature headers",
        )

    try:
        items = json.loads(body_bytes.decode("utf-8"))
        if not isinstance(items, list):
            raise ValueError("Expected a JSON array of events")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Malformed JSON batch: {e}",
        )

    try:
        result = await gateway.ingest_batch_async(
            events=items,
            raw_bytes=body_bytes,
            signature=x_honeypot_signature,
            timestamp=x_honeypot_timestamp,
        )
        return result
    except IngestionAuthenticationError as ae:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(ae))
    except IngestionBackpressureError as be:
        return Response(
            content=json.dumps({"detail": str(be), "retry_after": 5}),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json",
            headers={"Retry-After": "5"},
        )
    except ValidationError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=ve.errors())
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/health", summary="Check ingestion gateway queue depth and status")
async def ingest_health(
    gateway: IngestionGateway = Depends(get_ingestion_gateway),
    _user: User = Depends(get_current_user),
):
    try:
        depth = await gateway.check_backpressure_async()
        return {
            "status": "healthy",
            "queue_depth": depth,
            "max_queue_depth": gateway.max_stream_len,
            "stream_key": gateway.stream_key,
        }
    except IngestionBackpressureError as be:
        return Response(
            content=json.dumps({
                "status": "degraded",
                "reason": "BACKPRESSURE_SATURATED",
                "queue_depth": be.current_len,
                "max_queue_depth": be.max_len,
            }),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json",
            headers={"Retry-After": "5"},
        )
    except Exception as e:
        return Response(
            content=json.dumps({"status": "unhealthy", "error": str(e)}),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )
