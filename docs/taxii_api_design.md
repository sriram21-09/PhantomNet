# TAXII 2.1 Feed Endpoint Architecture & API Design Spec

**Author:** Team Lead (`sriram21-09`)  
**Project:** PhantomNet (Sentinel Layer)  
**Milestone:** Month 5 – LLM Integration & Advanced Features (Week 18)  
**Issue:** #862 — Design TAXII 2.1 Feed Endpoint Architecture  
**Status:** Approved Architecture Spec  

---

## 1. Executive Summary & System Context

The PhantomNet Sentinel layer automatically analyzes honeypot threat events (e.g. SSH brute force, SQL injection, port scans), maps them to MITRE ATT&CK techniques, calculates composite threat confidence scores, and generates automated response playbooks with embedded Snort rules and STIX 2.1 threat intelligence.

To enable seamless inter-operation with external **Security Information and Event Management (SIEM)** systems, **Security Orchestration, Automation, and Response (SOAR)** platforms, and **Threat Intelligence Platforms (TIPs)** such as MISP, OpenCTI, Anomali, and Splunk, PhantomNet requires a standard threat feed server.

This document defines the architecture, API contract, JSON schemas, content negotiation rules, and data access layer for exposing approved `SentinelPlaybook` records via a custom **TAXII 2.1 Server** integrated into the PhantomNet FastAPI backend.

```
+-----------------------------------------------------------------------------------+
|                              External Consumers                                   |
|                (MISP, OpenCTI, Splunk, taxii2-client, Sentinel SOAR)             |
+-----------------------------------------------------------------------------------+
                                         |
                       HTTP GET (Strict Media Type Negotiation)
                                         v
+-----------------------------------------------------------------------------------+
|                        PhantomNet FastAPI Backend                                 |
|                                                                                   |
|  +-----------------------+   +------------------------+   +--------------------+  |
|  | GET /taxii2/          |   | GET /taxii2/phantomnet/|   | GET .../collections|  |
|  | Discovery Endpoint    |   | API Root Information   |   | Collections list   |  |
|  +-----------------------+   +------------------------+   +--------------------+  |
|                                                                     |             |
|                                                                     v             |
|                                                      +----------------------------+
|                                                      | GET .../objects/           |
|                                                      | Objects retrieval endpoint |
|                                                      +----------------------------+
|                                                                     |             |
|                                                                     v             |
|  +-------------------------------------------------------------------------------+ |
|  | Data Access & Transformation Layer                                            | |
|  |  - Query DB: SELECT * FROM sentinel_playbooks WHERE status = 'approved'        | |
|  |  - Filter by `added_after` parameter                                           | |
|  |  - Transform using `stix_enhanced.build_stix_bundle()`                       | |
|  +-------------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             SQLite Database                                       |
|                         `sentinel_playbooks` Table                                |
+-----------------------------------------------------------------------------------+
```

---

## 2. Protocol Compliance & Media Types

The TAXII 2.1 specification (OASIS Standard) defines strict content-type negotiation requirements. Requests and responses must explicitly state protocol media types.

### 2.1 Supported Media Types
- **TAXII Metadata Response Media Type:** `application/taxii+json;version=2.1`
- **STIX Objects Response Media Type:** `application/stix+json;version=2.1`

### 2.2 Content Negotiation & Header Rules
1. **Request `Accept` Header Validation:**
   - Discovery, API Root, and Collection endpoints MUST receive `Accept: application/taxii+json;version=2.1` (or wildcards `application/*`, `*/*`).
   - Objects endpoints MUST receive `Accept: application/stix+json;version=2.1` or `application/taxii+json;version=2.1`.
2. **Rejection Handling (HTTP 406):**
   - If an explicit `Accept` header is provided that demands an unsupported media type (e.g., `text/html`, `application/xml`), the server MUST reject the request with HTTP Status `406 Not Acceptable` and a `TaxiiErrorResponse` body.
3. **Response Headers:**
   - Responses from metadata endpoints MUST include header:  
     `Content-Type: application/taxii+json;version=2.1`
   - Responses from object retrieval endpoints MUST include header:  
     `Content-Type: application/stix+json;version=2.1`

---

## 3. API Routing Table & Endpoints Contract

All TAXII 2.1 endpoints are mounted under the `/taxii2/` route prefix in FastAPI.

| Method | Endpoint Path | Required `Accept` Header | Response Model | Description |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/taxii2/` | `application/taxii+json;version=2.1` | `TaxiiDiscoveryResponse` | Returns TAXII 2.1 server metadata and hosted API root URLs. |
| `GET` | `/taxii2/phantomnet/` | `application/taxii+json;version=2.1` | `TaxiiApiRootResponse` | Returns metadata, supported TAXII versions, and max size for the `phantomnet` API root. |
| `GET` | `/taxii2/phantomnet/collections/` | `application/taxii+json;version=2.1` | `TaxiiCollectionsResponse` | Lists all threat intelligence collections available under this API root. |
| `GET` | `/taxii2/phantomnet/collections/{collection_id}/` | `application/taxii+json;version=2.1` | `TaxiiCollectionResource` | Returns detailed metadata for a specific collection. |
| `GET` | `/taxii2/phantomnet/collections/{collection_id}/objects/` | `application/stix+json;version=2.1` | `stix2.Bundle` / `TaxiiEnvelopeResponse` | Queries database for approved playbooks and returns STIX 2.1 bundle. |

---

## 4. Endpoint Specifications & JSON Schemas

### 4.1 Server Discovery — `GET /taxii2/`

- **Purpose:** Entry point for TAXII clients to discover available API roots and contact details.
- **Request Headers:**
  - `Accept: application/taxii+json;version=2.1`
- **Response HTTP 200 Body Schema (`TaxiiDiscoveryResponse`):**
  ```json
  {
    "title": "PhantomNet TAXII 2.1 Server",
    "description": "TAXII 2.1 Feed Server exposing Sentinel STIX 2.1 threat intelligence bundles.",
    "contact": "security@phantomnet.io",
    "default": "/taxii2/phantomnet/",
    "api_roots": [
      "/taxii2/phantomnet/"
    ]
  }
  ```

### 4.2 API Root Information — `GET /taxii2/phantomnet/`

- **Purpose:** Describes the capabilities of the primary `phantomnet` API root.
- **Request Headers:**
  - `Accept: application/taxii+json;version=2.1`
- **Response HTTP 200 Body Schema (`TaxiiApiRootResponse`):**
  ```json
  {
    "title": "PhantomNet Sentinel API Root",
    "description": "Primary API Root providing access to approved Sentinel threat playbooks and IOC bundles.",
    "versions": [
      "taxii-2.1"
    ],
    "max_content_length": 10485760
  }
  ```

### 4.3 Collections List — `GET /taxii2/phantomnet/collections/`

- **Purpose:** Enumerates the collections provided by the `phantomnet` API root.
- **Request Headers:**
  - `Accept: application/taxii+json;version=2.1`
- **Response HTTP 200 Body Schema (`TaxiiCollectionsResponse`):**
  ```json
  {
    "collections": [
      {
        "id": "sentinel-playbooks-approved",
        "title": "Approved Sentinel Playbooks",
        "description": "STIX 2.1 bundles generated from approved PhantomNet honeypot threat detections.",
        "alias": "approved-playbooks",
        "can_read": true,
        "can_write": false,
        "media_types": [
          "application/stix+json;version=2.1"
        ]
      }
    ]
  }
  ```

### 4.4 Specific Collection Resource — `GET /taxii2/phantomnet/collections/{collection_id}/`

- **Purpose:** Fetch metadata for a given collection ID.
- **Path Parameters:**
  - `collection_id`: String (e.g. `sentinel-playbooks-approved`).
- **Error Behavior:** Returns `404 Not Found` if `collection_id` is unknown.
- **Response HTTP 200 Body Schema (`TaxiiCollectionResource`):**
  ```json
  {
    "id": "sentinel-playbooks-approved",
    "title": "Approved Sentinel Playbooks",
    "description": "STIX 2.1 bundles generated from approved PhantomNet honeypot threat detections.",
    "alias": "approved-playbooks",
    "can_read": true,
    "can_write": false,
    "media_types": [
      "application/stix+json;version=2.1"
    ]
  }
  ```

### 4.5 Objects Retrieval — `GET /taxii2/phantomnet/collections/{collection_id}/objects/`

- **Purpose:** Retrieves threat intelligence objects (STIX 2.1 Bundle) for approved playbooks.
- **Path Parameters:**
  - `collection_id`: Must equal `sentinel-playbooks-approved` (or alias `approved-playbooks`).
- **Query Parameters:**
  - `added_after`: Optional string. ISO 8601 / RFC 3339 UTC timestamp filter (e.g. `2026-07-20T00:00:00Z`). Only return objects created/updated after this time.
  - `limit`: Optional integer. Maximum number of playbooks to return (default: 50, max: 200).
- **Request Headers:**
  - `Accept: application/stix+json;version=2.1` (or `application/taxii+json;version=2.1`)
- **Response HTTP 200 Body Schema (`stix2.Bundle` serialized):**
  ```json
  {
    "type": "bundle",
    "id": "bundle--37a85816-5e0c-5192-944b-6eeae03ba67e",
    "objects": [
      {
        "type": "identity",
        "id": "identity--e11fa6df-cfc5-555e-9905-fecce0e6bf30",
        "name": "PhantomNet Sentinel",
        "identity_class": "system"
      },
      {
        "type": "marking-definition",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "definition_type": "tlp",
        "name": "TLP:WHITE"
      },
      {
        "type": "attack-pattern",
        "id": "attack-pattern--0e817926-218d-5eb4-a36c-9411648a733e",
        "name": "Brute Force: Password Guessing",
        "external_references": [
          {
            "source_name": "mitre-attack",
            "external_id": "T1110.001"
          }
        ]
      },
      {
        "type": "indicator",
        "id": "indicator--e50153ef-62e5-55f7-8761-0498dbca2ff7",
        "pattern": "[ipv4-addr:value = '192.168.1.100']",
        "pattern_type": "stix"
      },
      {
        "type": "relationship",
        "id": "relationship--c6081498-5cce-5d29-bdf3-80e98c9dbbf7",
        "relationship_type": "indicates",
        "source_ref": "indicator--e50153ef-62e5-55f7-8761-0498dbca2ff7",
        "target_ref": "attack-pattern--0e817926-218d-5eb4-a36c-9411648a733e"
      }
    ]
  }
  ```

---

## 5. Data Access Layer & Retrieval Logic

### 5.1 Database Query Strategy
The TAXII server retrieves records from the `sentinel_playbooks` table using SQLAlchemy.

- **Source ORM Model:** `backend.sentinel.models.SentinelPlaybook`
- **Filter Clauses:**
  1. `SentinelPlaybook.status == "approved"`  
     *Security Rule: Only analyst-approved playbooks are published to the TAXII feed.*
  2. `SentinelPlaybook.updated_at > added_after_dt` (if `added_after` query parameter is supplied).
- **Ordering:** `SentinelPlaybook.updated_at.desc()`
- **Limit:** Applied via `.limit(limit_val)`.

### 5.2 Bundle Assembly & Deduplication
When converting multiple `SentinelPlaybook` records into a single STIX 2.1 Bundle:

1. **Iterate Playbook Records:**
   - Extract threat context: `technique_id`, `technique_name`, `tactic`, `mitre_url`, `src_ip`, `dst_port`, `protocol`, `threat_score`, `confidence_score`, `severity`.
   - Build technique dict for `stix_enhanced.build_stix_bundle()`:
     ```python
     technique = {
         "technique_id": playbook.technique_id or "T1110.001",
         "technique_name": playbook.technique_name or "Brute Force",
         "tactic": playbook.tactic or "Credential Access",
         "url": playbook.mitre_url or "https://attack.mitre.org/",
         "severity": playbook.severity or "HIGH",
     }
     ```
   - Build IOC list from `playbook.src_ip` (and any associated domains/URLs parsed from `playbook_content`).
   - Call `build_stix_bundle(technique, iocs, src_ip=playbook.src_ip, threat_score=playbook.threat_score)` to obtain individual STIX bundles per playbook.

2. **Deduplicate & Merge STIX Objects:**
   - Collect all STIX objects across all generated bundles into a single list.
   - Use deterministic STIX IDs (supported by `stix_enhanced.py`) to deduplicate:
     - `PHANTOMNET_IDENTITY` (always 1 instance).
     - `TLP_WHITE` / `TLP_GREEN` Marking Definitions (always 1 instance per TLP level).
     - Identical `AttackPattern` objects for repeated techniques.
     - Identical `Indicator` objects for repeated attacker IPs.
3. **Assemble Unified STIX Bundle:**
   - Package merged deduplicated objects into a single `stix2.Bundle`.
   - Return formatted JSON string via FastAPI `Response(content=bundle_json, media_type="application/stix+json;version=2.1")`.

---

## 6. Error Handling & Status Codes

All endpoint error responses follow the standard `TaxiiErrorResponse` format:

```json
{
  "title": "Not Acceptable",
  "description": "The requested Accept header 'text/html' is not supported by TAXII 2.1. Expected 'application/taxii+json;version=2.1' or 'application/stix+json;version=2.1'.",
  "http_status": "406"
}
```

| HTTP Status Code | Condition | Error Title | Error Action |
| :--- | :--- | :--- | :--- |
| `400 Bad Request` | Invalid `added_after` timestamp or malformed query string. | Bad Request | Client should correct query parameters. |
| `404 Not Found` | Requested `collection_id` does not exist (e.g. `/collections/invalid-id/`). | Collection Not Found | Client should query `/collections/` first. |
| `406 Not Acceptable` | Client `Accept` header conflicts with TAXII 2.1 spec. | Not Acceptable | Client must set correct `Accept` header. |
| `500 Internal Error` | Unexpected database error or STIX serialization failure. | Internal Server Error | Server logs exception details. |

---

## 7. Delivery Roadmap & Task Division (Week 18)

- **Day 1 (Team Lead):** Design Spec & Contract (`docs/taxii_api_design.md`) + Pydantic Schemas (`backend/schemas/taxii.py`). *(Completed)*
- **Day 1 (AI/ML Dev):** Initial FastAPI router (`backend/api/taxii.py`) & Discovery endpoint (`GET /taxii2/`).
- **Day 2 (Team Lead):** Collections metadata endpoint (`GET /taxii2/phantomnet/collections/`).
- **Day 2 (AI/ML Dev):** Objects retrieval endpoint (`GET /taxii2/phantomnet/collections/{id}/objects/`).
- **Day 3 (Team Lead):** Content-Type negotiation middleware & strict media type checks (HTTP 406).
- **Day 3 (AI/ML Dev):** Automated testing with official `taxii2-client` python package.
- **Day 4 (Team Lead):** `added_after` timestamp parameter filtering on objects endpoint.
- **Day 4 (AI/ML Dev):** Comprehensive pytest suite in `tests/test_taxii.py`.
- **Day 5 (Team Lead):** E2E verification & Interoperability documentation (`docs/taxii_interoperability.md`).
