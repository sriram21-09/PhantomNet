"""
backend/schemas/taxii.py
-------------------------
Pydantic schemas for PhantomNet TAXII 2.1 Feed Server.

Implements OASIS TAXII 2.1 Specification data structures for:
  - Server Discovery (GET /taxii2/)
  - API Root Information (GET /taxii2/phantomnet/)
  - Collections List & Detail (GET /taxii2/phantomnet/collections/[{id}/])
  - Envelope / Bundle Objects (GET /taxii2/phantomnet/collections/{id}/objects/)
  - TAXII 2.1 Error Responses
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class TaxiiDiscoveryResponse(BaseModel):
    """
    TAXII 2.1 Server Discovery Response Model (GET /taxii2/).
    Information about the server and its available API roots.
    """
    model_config = ConfigDict(populate_by_name=True)

    title: str = Field(
        default="PhantomNet TAXII 2.1 Server",
        description="A name or title for this TAXII server.",
        example="PhantomNet TAXII 2.1 Server",
    )
    description: Optional[str] = Field(
        default="TAXII 2.1 Feed Server exposing Sentinel STIX 2.1 threat intelligence bundles.",
        description="A human-readable description of this TAXII server.",
    )
    contact: Optional[str] = Field(
        default="security@phantomnet.io",
        description="Contact information for the administrator of this TAXII server.",
    )
    default: Optional[str] = Field(
        default="/taxii2/phantomnet/",
        description="The default API Root URL for clients that do not specify one.",
    )
    api_roots: List[str] = Field(
        default_factory=lambda: ["/taxii2/phantomnet/"],
        description="A list of URLs indicating the API Roots hosted by this server.",
    )


class TaxiiApiRootResponse(BaseModel):
    """
    TAXII 2.1 API Root Information Model (GET /taxii2/phantomnet/).
    Metadata regarding a specific API root.
    """
    model_config = ConfigDict(populate_by_name=True)

    title: str = Field(
        default="PhantomNet Sentinel API Root",
        description="A human-readable title for this API Root.",
    )
    description: Optional[str] = Field(
        default="Primary API Root providing access to approved Sentinel threat playbooks and IOC bundles.",
        description="A human-readable description of this API Root.",
    )
    versions: List[str] = Field(
        default_factory=lambda: ["taxii-2.1"],
        description="The versions of TAXII supported by this API Root.",
    )
    max_content_length: int = Field(
        default=10485760,  # 10 MB
        description="The maximum size of a request/response payload in bytes supported by this API Root.",
    )


class TaxiiCollectionResource(BaseModel):
    """
    TAXII 2.1 Collection Resource Model.
    Represents a single STIX collection resource.
    """
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(
        ...,
        description="A unique identifier for this collection.",
        example="sentinel-playbooks-approved",
    )
    title: str = Field(
        ...,
        description="A human-readable name for this collection.",
        example="Approved Sentinel Playbooks",
    )
    description: Optional[str] = Field(
        None,
        description="A human-readable description of this collection.",
        example="STIX 2.1 bundles generated from approved PhantomNet honeypot threat detections.",
    )
    alias: Optional[str] = Field(
        None,
        description="An optional human-readable alias for this collection.",
    )
    can_read: bool = Field(
        default=True,
        description="Indicates whether the user/client can read objects from this collection.",
    )
    can_write: bool = Field(
        default=False,
        description="Indicates whether the user/client can write objects to this collection.",
    )
    media_types: List[str] = Field(
        default_factory=lambda: ["application/stix+json;version=2.1"],
        description="A list of supported media types for objects in this collection.",
    )


class TaxiiCollectionsResponse(BaseModel):
    """
    TAXII 2.1 Collections List Response Model (GET /taxii2/phantomnet/collections/).
    Container listing all collections provided by an API Root.
    """
    model_config = ConfigDict(populate_by_name=True)

    collections: List[TaxiiCollectionResource] = Field(
        default_factory=list,
        description="A list of collection resources.",
    )


class TaxiiEnvelopeResponse(BaseModel):
    """
    TAXII 2.1 Envelope / Objects Response Model (GET /taxii2/phantomnet/collections/{id}/objects/).
    Serves STIX objects wrapped in a TAXII envelope or standard bundle.
    """
    model_config = ConfigDict(populate_by_name=True)

    more: Optional[bool] = Field(
        default=False,
        description="True if there are more objects available beyond this page.",
    )
    next: Optional[str] = Field(
        default=None,
        description="Pagination cursor token to fetch the next page of objects.",
    )
    objects: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of STIX 2.1 cyber threat intelligence objects.",
    )


class TaxiiErrorResponse(BaseModel):
    """
    TAXII 2.1 Error Message Resource.
    Returned when a request fails or is rejected (e.g. 406 Not Acceptable, 404 Not Found).
    """
    model_config = ConfigDict(populate_by_name=True)

    title: str = Field(
        ...,
        description="A human-readable brief summary of the error.",
        example="Not Acceptable",
    )
    description: Optional[str] = Field(
        None,
        description="A human-readable detailed message explaining the error.",
        example="Accept header must be 'application/taxii+json;version=2.1' or 'application/stix+json;version=2.1'",
    )
    error_id: Optional[str] = Field(
        None,
        description="An identifier for this error instance (e.g. UUID).",
    )
    error_code: Optional[str] = Field(
        None,
        description="An application error code.",
    )
    http_status: str = Field(
        ...,
        description="The HTTP status code associated with this error.",
        example="406",
    )
    details: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional debugging details or parameters.",
    )
