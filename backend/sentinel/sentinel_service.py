"""
backend/sentinel/sentinel_service.py
--------------------------------------
PhantomNet Sentinel Layer ΓÇö Orchestration Service

Wires together the four Sentinel sub-modules into a single pipeline:

    mitre_mapper  ΓåÆ  rule_generator  ΓåÆ  stix_enhanced  ΓåÆ  playbook_generator

Campaign clustering output has NO attack_type field ΓÇö it only returns:
    source_ips, target_ports, protocols, event_count, time_range

This service performs a 4-step inference process:

    1. Infer protocol/service from target_ports:
         2222 ΓåÆ SSH,  8080 ΓåÆ HTTP,  2121 ΓåÆ FTP,  2525 ΓåÆ SMTP
    2. Query PacketLog for matching IPs + timestamps to retrieve threat_levels
    3. Optionally query events table for raw_data to run
       SignatureEngine.check_signatures()
    4. Use inferred signature name to call mitre_mapper.get_technique()
    5. Store the result in PacketLog.detected_signatures for matched log entries

ΓÜá∩╕Å  Do NOT modify threat_analyzer.py ΓÇö campaign clustering runs separately
    via API, not inside the ThreatAnalyzer loop.

Public API
----------
    SentinelService(db_session)
        Instantiate with a SQLAlchemy session.

    SentinelService.create_and_run(campaign_data) -> SentinelPlaybook
        Class-level convenience: creates session, runs pipeline, closes session.

    generate_playbook(campaign_data) -> SentinelPlaybook
        Full pipeline: infer ΓåÆ query ΓåÆ map ΓåÆ generate rules ΓåÆ build STIX
        ΓåÆ render playbook ΓåÆ persist SentinelPlaybook row ΓåÆ return ORM object.

Phase 5, Week 2 (Week 14), Day 1 ΓÇö Integration & API
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks
from sqlalchemy.orm import Session

# Sentinel sub-modules
from sentinel.mitre_mapper import map_signature, map_signatures
from sentinel.rule_generator import generate_rules_for_campaign
from sentinel.stix_enhanced import build_stix_bundle, bundle_to_json
from sentinel.models import SentinelPlaybook
from sentinel.confidence_scoring import calculate_confidence, ConfidenceResult

# Database models and session
from database.models import PacketLog, Event, IOC
from database.database import SessionLocal

# ML signature engine
from ml.signatures import SignatureEngine

logger = logging.getLogger("sentinel.service")

# ---------------------------------------------------------------------------
# Port ΓåÆ Service mapping (honeypot port assignments)
# ---------------------------------------------------------------------------
_PORT_SERVICE_MAP: Dict[int, str] = {
    2222: "SSH",
    22:   "SSH",
    8080: "HTTP",
    80:   "HTTP",
    443:  "HTTP",
    2121: "FTP",
    21:   "FTP",
    2525: "SMTP",
    25:   "SMTP",
}

# Service ΓåÆ default signature name (used when SignatureEngine has no raw_data)
_SERVICE_DEFAULT_SIGNATURE: Dict[str, str] = {
    "SSH":  "SSH_AUTH_FAILURE",
    "HTTP": "HTTP_SCANNER_BEHAVIOR",
    "FTP":  "FTP_DATA_EXFILTRATION",
    "SMTP": "SMTP_LARGE_PAYLOAD",
}


# ---------------------------------------------------------------------------
# Playbook ID generator
# ---------------------------------------------------------------------------
def _generate_playbook_id() -> str:
    """Generate a unique playbook ID with timestamp and random suffix.

    Format: ``PB-YYYYMMDD-HHMMSS-XXXXXX`` where ``XXXXXX`` is a random
    6-character hex string derived from UUID4.

    Returns:
        A unique playbook identifier string.
    """
    import uuid
    now = datetime.now(tz=timezone.utc)
    suffix = uuid.uuid4().hex[:6].upper()
    return f"PB-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}-{suffix}"


def _run_llm_narrative_bg(playbook_id: int) -> None:
    """Generate and persist the LLM narrative for a playbook in a separate session.

    This runs in a background thread or task, avoiding database write contention
    on the main request thread's session.
    """
    from database.database import SessionLocal
    from sentinel.models import SentinelPlaybook
    from sentinel.llm_service import LLMService

    db = SessionLocal()
    try:
        playbook = db.query(SentinelPlaybook).filter(SentinelPlaybook.id == playbook_id).first()
        if not playbook:
            logger.error("Playbook %d not found for background LLM narrative generation.", playbook_id)
            return

        context_data = {
            "attack_type": playbook.attack_type,
            "severity": playbook.severity,
            "src_ip": playbook.src_ip,
            "dst_port": playbook.dst_port,
            "protocol": playbook.protocol,
            "technique_id": playbook.technique_id,
            "technique_name": playbook.technique_name,
            "tactic": playbook.tactic,
            "threat_score": playbook.threat_score,
            "playbook_name": playbook.playbook_name,
        }

        llm_svc = LLMService()
        narrative = llm_svc.generate_narrative(context_data)
        if narrative:
            playbook.llm_narrative = narrative
            playbook.updated_at = datetime.utcnow()
            db.commit()
            logger.info("Successfully persisted LLM narrative for playbook %d in background.", playbook_id)
        else:
            logger.warning("LLMService returned empty narrative for playbook %d in background.", playbook_id)
    except Exception as exc:
        logger.error("Failed to generate background LLM narrative for playbook %d: %s", playbook_id, exc)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# SentinelService
# ---------------------------------------------------------------------------
class SentinelService:
    """Orchestration service that connects all Sentinel sub-modules.

    Parameters
    ----------
    db : sqlalchemy.orm.Session
        Active database session for querying PacketLog / Event tables and
        persisting SentinelPlaybook rows.

    Attributes
    ----------
    db : Session
        The database session passed at construction time.
    sig_engine : SignatureEngine
        Instance of the ML signature engine for raw payload analysis.
    playbook_gen : PlaybookGenerator | None
        Lazy-loaded PlaybookGenerator (imported on first use to avoid
        circular-import issues with Jinja2 template discovery).
    """

    _seen_campaigns = {}

    def __init__(self, db: Session) -> None:
        """Initialise the SentinelService with a database session.

        Args:
            db: Active SQLAlchemy session for querying and persisting data.
        """
        self.db = db
        self.sig_engine = SignatureEngine()
        self._playbook_gen = None  # lazy-loaded
        import os
        if os.environ.get("ENVIRONMENT") == "test":
            self.__class__._seen_campaigns.clear()

    # ------------------------------------------------------------------
    # Lazy loader for PlaybookGenerator
    # ------------------------------------------------------------------
    @property
    def playbook_gen(self) -> Optional[Any]:
        """Lazy-load PlaybookGenerator to avoid import-time side effects.

        Attempts import from backend/sentinel first, then falls back to
        the root sentinel package where PlaybookGenerator and its Jinja2
        templates actually reside.

        Returns:
            A PlaybookGenerator instance, or None if unavailable.
        """
        if self._playbook_gen is None:
            # Try backend/sentinel first
            try:
                from sentinel.playbook_generator import PlaybookGenerator  # noqa: F811
                self._playbook_gen = PlaybookGenerator()
            except Exception:
                pass

            # Fallback: root-level sentinel package where templates reside
            if self._playbook_gen is None:
                try:
                    import os
                    import sys as _sys
                    root_dir = os.path.abspath(
                        os.path.join(os.path.dirname(__file__), "..", "..")
                    )
                    if root_dir not in _sys.path:
                        _sys.path.insert(0, root_dir)
                    from importlib import import_module
                    _mod = import_module("sentinel.playbook_generator")
                    self._playbook_gen = _mod.PlaybookGenerator()
                    logger.info(
                        "PlaybookGenerator loaded from root sentinel package"
                    )
                except Exception:
                    logger.warning(
                        "PlaybookGenerator not available \u2014 playbook rendering "
                        "will return a placeholder."
                    )
        return self._playbook_gen

    # ------------------------------------------------------------------
    # Class-level convenience: session lifecycle management
    # ------------------------------------------------------------------
    @classmethod
    def create_and_run(
        cls, campaign_data: Dict[str, Any]
    ) -> SentinelPlaybook:
        """Create a DB session, run the full pipeline, close the session.

        This is the recommended entry point for callers that do not
        already hold an open SQLAlchemy session.  The session is
        created from the existing ``SessionLocal`` factory, used for
        the entire pipeline, and closed in the ``finally`` block.

        Args:
            campaign_data: Campaign clustering output dict.

        Returns:
            The persisted SentinelPlaybook ORM object (detached from
            the now-closed session ΓÇö all attributes are eagerly loaded
            before close).

        Raises:
            Exception: Re-raises any pipeline error after session cleanup.
        """
        db = SessionLocal()
        try:
            svc = cls(db)
            playbook = svc.generate_playbook(campaign_data)
            return playbook
        except Exception:
            db.rollback()
            logger.error("create_and_run pipeline failed for campaign_data keys=%s",
                         list(campaign_data.keys()), exc_info=True)
            raise
        finally:
            db.close()
            logger.info("DB session closed (create_and_run)")

    # ------------------------------------------------------------------
    # Step 1: Infer service type from target ports
    # ------------------------------------------------------------------
    def _infer_service(self, target_ports: List[int]) -> str:
        """Infer the honeypot service type from a list of target ports.

        Uses the first recognised port.  Falls back to ``"UNKNOWN"`` if
        no port in the list matches a known honeypot service.

        Args:
            target_ports: List of destination port numbers from campaign data.

        Returns:
            Service name string: ``"SSH"`` | ``"HTTP"`` | ``"FTP"`` |
            ``"SMTP"`` | ``"UNKNOWN"``.
        """
        for port in target_ports:
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                continue
            service = _PORT_SERVICE_MAP.get(port_int)
            if service:
                logger.debug("Port %d -> service %s", port_int, service)
                return service

        logger.warning(
            "No recognised service for ports %s - defaulting to UNKNOWN",

            target_ports,
        )
        return "UNKNOWN"

    # ------------------------------------------------------------------
    # Step 2: Query PacketLog for matching IPs + time window
    # ------------------------------------------------------------------
    def _query_packet_logs(
        self,
        source_ips: List[str],
        target_ports: List[int],
        time_range: Optional[Dict[str, Any]] = None,
    ) -> List[PacketLog]:
        """Query PacketLog rows that match the campaign's source IPs and ports.

        Args:
            source_ips:   List of attacker source IP strings.
            target_ports: List of destination port integers.
            time_range:   Optional dict with ``start`` and ``end`` keys
                          (ISO-8601 strings or datetime objects).

        Returns:
            List of matching PacketLog ORM objects.
        """
        query = self.db.query(PacketLog).filter(
            PacketLog.src_ip.in_(source_ips),
        )

        # Filter by destination ports if available
        int_ports = []
        for p in target_ports:
            try:
                int_ports.append(int(p))
            except (TypeError, ValueError):
                continue
        if int_ports:
            query = query.filter(PacketLog.dst_port.in_(int_ports))

        # Apply time window filter if provided
        if time_range:
            start = time_range.get("start")
            end = time_range.get("end")
            if start:
                if isinstance(start, str):
                    try:
                        start = datetime.fromisoformat(start)
                    except ValueError:
                        pass
                if isinstance(start, datetime):
                    query = query.filter(PacketLog.timestamp >= start)
            if end:
                if isinstance(end, str):
                    try:
                        end = datetime.fromisoformat(end)
                    except ValueError:
                        pass
                if isinstance(end, datetime):
                    query = query.filter(PacketLog.timestamp <= end)

        results = query.order_by(PacketLog.timestamp.desc()).limit(500).all()
        logger.info(
            "PacketLog query: %d rows matched (ips=%d, ports=%s, time_range=%s)",
            len(results), len(source_ips), int_ports,
            "yes" if time_range else "no",
        )
        return results

    # ------------------------------------------------------------------
    # Step 2b: Query IOC table for enrichment
    # ------------------------------------------------------------------
    def _query_iocs(
        self,
        source_ips: List[str],
    ) -> List[Any]:
        """Query the IOC table for entries matching the campaign's source IPs.

        This enriches the pipeline with threat intelligence previously
        ingested into the IOC table (IP-type indicators, watchlist flags,
        threat_level ratings).

        Args:
            source_ips: List of attacker source IP strings.

        Returns:
            List of matching IOC ORM objects.
        """
        if not source_ips:
            return []

        try:
            ioc_rows = (
                self.db.query(IOC)
                .filter(
                    IOC.type == "IP",
                    IOC.value.in_(source_ips),
                )
                .all()
            )
            logger.info(
                "IOC query: %d rows matched for %d source IPs",
                len(ioc_rows), len(source_ips),
            )
            return ioc_rows
        except Exception as exc:
            logger.warning("IOC query failed: %s - continuing without IOC enrichment", exc)

            return []

    # ------------------------------------------------------------------
    # Derive max threat_level string from IOC rows
    # ------------------------------------------------------------------
    @staticmethod
    def _max_ioc_threat_level(ioc_rows: List[Any]) -> Optional[str]:
        """Return the highest threat_level from matched IOC rows."""
        level_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        best_level = None
        best_rank = 0
        for ioc in ioc_rows:
            lvl = getattr(ioc, "threat_level", None) or "Medium"
            rank = level_order.get(lvl, 2)
            if rank > best_rank:
                best_rank = rank
                best_level = lvl
        return best_level

    # ------------------------------------------------------------------
    # Step 3: Run SignatureEngine on events for matched IPs
    # ------------------------------------------------------------------
    def _run_signature_analysis(
        self,
        source_ips: List[str],
        service_type: str,
    ) -> List[str]:
        """Query the events table and run SignatureEngine on raw payloads.

        Args:
            source_ips:   List of attacker source IPs.
            service_type: Inferred service (SSH, HTTP, FTP, SMTP).

        Returns:
            Deduplicated list of detected signature names.
        """
        detected: set = set()

        try:
            events = (
                self.db.query(Event)
                .filter(Event.source_ip.in_(source_ips))
                .order_by(Event.timestamp.desc())
                .limit(200)
                .all()
            )
        except Exception as exc:
            logger.warning("Events query failed: %s - using default signature", exc)

            default_sig = _SERVICE_DEFAULT_SIGNATURE.get(service_type)
            return [default_sig] if default_sig else []

        for event in events:
            log_entry = {
                "service_type": service_type,
                "payload": event.raw_data or "",
                "status": "Failed" if service_type == "SSH" else "",
                "payload_size": len(event.raw_data or ""),
            }
            sigs, _ = self.sig_engine.check_signatures(log_entry)
            detected.update(sigs)

        # If no signatures found from events, use the default for service type
        if not detected:
            default_sig = _SERVICE_DEFAULT_SIGNATURE.get(service_type)
            if default_sig:
                detected.add(default_sig)
                logger.debug(
                    "No event-based signatures ΓÇö using default: %s", default_sig
                )

        return list(detected)

    # ------------------------------------------------------------------
    # Step 4: Store detected_signatures in PacketLog rows
    # ------------------------------------------------------------------
    def _store_signatures(
        self,
        packet_logs: List[PacketLog],
        signature_names: List[str],
    ) -> int:
        """Write detected signature names into PacketLog.detected_signatures.

        Args:
            packet_logs:     List of PacketLog ORM objects to update.
            signature_names: List of signature name strings to store.

        Returns:
            Number of rows updated.
        """
        if not signature_names or not packet_logs:
            return 0

        sig_str = ",".join(sorted(set(signature_names)))
        updated = 0

        for pkt in packet_logs:
            if pkt.detected_signatures != sig_str:
                pkt.detected_signatures = sig_str
                updated += 1

        if updated > 0:
            try:
                self.db.commit()
                logger.info(
                    "Stored detected_signatures on %d PacketLog rows: %s",
                    updated, sig_str,
                )
            except Exception as exc:
                self.db.rollback()
                logger.error("Failed to commit detected_signatures: %s", exc)
                raise

        return updated

    # ------------------------------------------------------------------
    # Collect ML anomaly scores from matched packet logs
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_ml_scores(packet_logs: List[PacketLog]) -> List[float]:
        """Extract all non-None, positive threat_score values from PacketLog rows.

        These are used as the ``ml_scores`` input to ``calculate_confidence()``.
        Scores are expected on the 0–100 scale (PacketLog.threat_score convention).

        Args:
            packet_logs: List of PacketLog ORM objects from Step 2 query.

        Returns:
            List of float threat scores.  Empty list when no valid scores exist.
        """
        return [
            float(p.threat_score)
            for p in packet_logs
            if p.threat_score is not None and p.threat_score > 0
        ]

    # ------------------------------------------------------------------
    # Extract average threat score from matched logs
    # ------------------------------------------------------------------
    @staticmethod
    def _avg_threat_score(packet_logs: List[PacketLog]) -> float:
        """Compute the average threat_score from matched PacketLog rows."""
        scores = [
            p.threat_score for p in packet_logs
            if p.threat_score is not None and p.threat_score > 0
        ]
        if not scores:
            return 0.0
        return round(sum(scores) / len(scores), 2)

    # ------------------------------------------------------------------
    # Core public API: generate_playbook()
    # ------------------------------------------------------------------
    def generate_playbook(
        self,
        campaign_data: Dict[str, Any],
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> SentinelPlaybook:
        """Full Sentinel pipeline for a single campaign cluster.

        Performs the complete inference and generation process:
          1. Infer service from target_ports
          2. Query PacketLog for matching IPs + timestamps ΓåÆ threat_levels
          2b. Query IOC table for threat intelligence enrichment
          3. Run SignatureEngine on events ΓåÆ detected signature names
          4. Map signatures via mitre_mapper ΓåÆ ATT&CK technique
          5. Generate Snort/Sigma rules via rule_generator
          6. Build enriched STIX 2.1 bundle via stix_enhanced
          7. Render playbook via playbook_generator (if available)
          8. Persist SentinelPlaybook row in DB
          9. Store detected_signatures in matched PacketLog rows

        Args:
            campaign_data: Campaign clustering output dict with keys:
                - source_ips:   list[str]
                - target_ports: list[int]
                - protocols:    list[str]
                - event_count:  int
                - time_range:   dict with start/end (optional)
                - campaign_id:  str (optional)

        Returns:
            SentinelPlaybook ORM object persisted in the database.
            The object carries a ``result_dict`` attribute with all
            generated artefacts for convenience.
        """
        logger.info("=" * 60)
        logger.info("SentinelService.generate_playbook() - START")

        logger.info("Campaign data keys: %s", list(campaign_data.keys()))
        campaign_id = campaign_data.get("campaign_id", "CAMP-UNKNOWN")

        # ΓöÇΓöÇ Deduplication Check ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        if campaign_id != "CAMP-UNKNOWN" and campaign_id in self.__class__._seen_campaigns:
            logger.info("Duplicate campaign %s detected - returning existing playbook", campaign_id)
            return self.__class__._seen_campaigns[campaign_id]

        # ΓöÇΓöÇ Extract campaign fields ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        source_ips = campaign_data.get("source_ips") or []
        target_ports = campaign_data.get("target_ports") or []
        protocols = campaign_data.get("protocols") or ["TCP"]
        event_count = campaign_data.get("event_count", 0)
        time_range = campaign_data.get("time_range")
        campaign_id = campaign_data.get("campaign_id", "CAMP-UNKNOWN")

        # Normalise source_ips to list of strings and deduplicate
        if isinstance(source_ips, str):
            source_ips = [source_ips]
        source_ips_dedup = []
        for ip in source_ips:
            if ip and str(ip) not in source_ips_dedup:
                source_ips_dedup.append(str(ip))
        source_ips = source_ips_dedup

        # Normalise target_ports to list of ints and deduplicate
        normalised_ports: List[int] = []
        for p in target_ports:
            try:
                p_int = int(p)
                if p_int not in normalised_ports:
                    normalised_ports.append(p_int)
            except (TypeError, ValueError):
                continue

        # Normalise protocols
        if isinstance(protocols, str):
            protocols = [protocols]
        protocol_str = protocols[0].upper() if protocols else "TCP"

        # ΓöÇΓöÇ Step 1: Infer service from target_ports ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        service_type = self._infer_service(normalised_ports)
        logger.info("Step 1 - Inferred service: %s (from ports %s)", service_type, normalised_ports)


        # ΓöÇΓöÇ Step 2: Query PacketLog ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        matched_logs = self._query_packet_logs(source_ips, normalised_ports, time_range)
        threat_score = self._avg_threat_score(matched_logs)
        logger.info("Step 2 - Matched %d PacketLog rows, avg threat_score=%.2f", len(matched_logs), threat_score)


        # ΓöÇΓöÇ Step 2b: Query IOC table for enrichment ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        ioc_rows = self._query_iocs(source_ips)
        ioc_threat_level = self._max_ioc_threat_level(ioc_rows)
        if ioc_threat_level:
            logger.info("Step 2b - IOC enrichment: %d IOCs, max threat_level=%s",
                        len(ioc_rows), ioc_threat_level)
        else:
            logger.info("Step 2b - No IOC matches found for source IPs")

        # ── Step 2c: Calculate confidence score ───────────────────────────
        ml_scores = self._collect_ml_scores(matched_logs)
        # unique_ioc_count = unique source IPs observed (IOC proxy from source_ips)
        unique_ioc_count = len(set(source_ips))
        confidence_result: ConfidenceResult = calculate_confidence(
            event_count=event_count,
            ml_scores=ml_scores,
            unique_ioc_count=unique_ioc_count,
            protocols=protocols,
            cluster_size_cap=200,
        )
        confidence_score = confidence_result.confidence
        confidence_severity = confidence_result.severity
        logger.info(
            "Step 2c - Confidence score: %.4f  severity=%s  "
            "(css=%.3f mlas=%.3f iod=%.3f mpb=%.1f)",
            confidence_score, confidence_severity,
            confidence_result.cluster_size_score,
            confidence_result.ml_avg_score,
            confidence_result.ioc_density,
            confidence_result.multi_proto_bonus,
        )

        # ── Step 3: Run SignatureEngine on events ─────────────────────────
        signature_names = self._run_signature_analysis(source_ips, service_type)
        logger.info("Step 3 - Detected signatures: %s", signature_names)


        # ΓöÇΓöÇ Step 4: Map signatures ΓåÆ MITRE ATT&CK ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        techniques = map_signatures(signature_names)
        primary_technique = techniques[0] if techniques else None

        # Fallback: use default signature for the service
        if primary_technique is None and service_type != "UNKNOWN":
            default_sig = _SERVICE_DEFAULT_SIGNATURE.get(service_type, "")
            primary_technique = map_signature(default_sig)
            if primary_technique:
                signature_names = [default_sig]

        # Ultimate fallback
        if primary_technique is None:
            primary_technique = {
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "tactic": "Discovery",
                "tactic_id": "TA0007",
                "description": "Unknown attack pattern ΓÇö default mapping.",
                "url": "https://attack.mitre.org/techniques/T1046/",
                "severity": "MEDIUM",
                "signature": "UNKNOWN",
            }
            if not signature_names:
                signature_names = ["UNKNOWN"]

        attack_type = signature_names[0] if signature_names else "UNKNOWN"
        logger.info("Step 4 - Primary technique: %s (%s)",

                     primary_technique.get("technique_id"), primary_technique.get("technique_name"))

        # ΓöÇΓöÇ Step 5: Generate Snort/Sigma rules ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        rules_result = generate_rules_for_campaign(
            campaign_data,
            techniques if techniques else primary_technique,
        )
        snort_rule = rules_result.get("snort_rules", "")
        sigma_rule = rules_result.get("sigma_rules", "")
        logger.info("Step 5 - Generated %d Snort + %d Sigma rules",

                     rules_result["metadata"]["snort_rule_count"],
                     rules_result["metadata"]["sigma_rule_count"])

        # ΓöÇΓöÇ Step 6: Build STIX 2.1 bundle ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        # Merge source IPs as IOCs + any IOC table entries
        iocs = [{"type": "ip", "value": ip} for ip in source_ips]
        for ioc_row in ioc_rows:
            ioc_entry = {"type": ioc_row.type.lower(), "value": ioc_row.value}
            if ioc_entry not in iocs:
                iocs.append(ioc_entry)
        src_ip_primary = source_ips[0] if source_ips else None

        # Use IOC threat_level to influence TLP if available
        if ioc_threat_level in ("Critical", "High") or threat_score >= 70:
            tlp = "amber"
        elif ioc_threat_level == "Medium" or threat_score >= 40:
            tlp = "green"
        else:
            tlp = "green"

        stix_bundle = build_stix_bundle(
            technique=primary_technique,
            iocs=iocs,
            src_ip=src_ip_primary,
            threat_score=threat_score,
            tlp_level=tlp,
        )
        stix_json = bundle_to_json(stix_bundle, pretty=True)
        logger.info("Step 6 - STIX bundle: %d objects, tlp=%s", len(stix_bundle.objects), tlp)


        # ΓöÇΓöÇ Step 7: Render playbook ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        playbook_name = f"{service_type} {primary_technique.get('technique_name', 'Response')} Playbook"
        template_name = None
        playbook_content = None

        if self.playbook_gen is not None:
            try:
                # Map service_type to attack_pattern for template selection
                service_pattern_map = {
                    "SSH": "brute_force",
                    "HTTP": "port_scan",
                    "FTP": "credential_reuse",
                    "SMTP": "distributed_attack",
                }
                attack_pattern = service_pattern_map.get(service_type, attack_type.lower())

                context = {
                    "attack_pattern": attack_pattern,
                    "source_ip": src_ip_primary or "N/A",
                    "target_ip": "honeypot-cluster",
                    "severity": primary_technique.get("severity", "HIGH"),
                    "generated_at": datetime.now(tz=timezone.utc).isoformat(),
                    "campaign_id": campaign_id,
                    "event_count": event_count,
                    "technique_id": primary_technique.get("technique_id"),
                    "technique_name": primary_technique.get("technique_name"),
                    "source_ips": source_ips,
                    "target_ports": normalised_ports,
                    "protocols": protocols,
                    "threat_score": threat_score,
                }
                playbook_content = self.playbook_gen.generate(context)
                template_name = self.playbook_gen._select_template(attack_pattern)
                logger.info("Step 7 - Playbook rendered: %d chars, template=%s",
                            len(playbook_content), template_name)
            except Exception as exc:
                logger.warning("Playbook rendering failed: %s - using placeholder", exc)

                playbook_content = (
                    f"# {playbook_name}\n\n"
                    f"Campaign: {campaign_id}\n"
                    f"Technique: {primary_technique.get('technique_id')} ΓÇö "
                    f"{primary_technique.get('technique_name')}\n"
                    f"Source IPs: {', '.join(source_ips)}\n"
                    f"Ports: {normalised_ports}\n"
                    f"Threat Score: {threat_score}\n"
                )
        else:
            playbook_content = (
                f"# {playbook_name}\n\n"
                f"Campaign: {campaign_id}\n"
                f"Technique: {primary_technique.get('technique_id')} ΓÇö "
                f"{primary_technique.get('technique_name')}\n"
                f"Source IPs: {', '.join(source_ips)}\n"
                f"Ports: {normalised_ports}\n"
                f"Threat Score: {threat_score}\n"
            )

        # ΓöÇΓöÇ Step 8: Persist SentinelPlaybook row ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        playbook_id = _generate_playbook_id()
        dst_port_primary = normalised_ports[0] if normalised_ports else None

        playbook_record = SentinelPlaybook(
            playbook_id=playbook_id,
            src_ip=src_ip_primary,
            dst_port=dst_port_primary,
            protocol=protocol_str,
            attack_type=attack_type,
            threat_score=threat_score,
            confidence_score=confidence_score,
            severity=confidence_severity,
            technique_id=primary_technique.get("technique_id"),
            technique_name=primary_technique.get("technique_name"),
            tactic=primary_technique.get("tactic"),
            mitre_url=primary_technique.get("url"),
            snort_rule=snort_rule if snort_rule else None,
            sigma_rule=sigma_rule if sigma_rule else None,

            playbook_name=playbook_name,
            playbook_content=playbook_content,
            template_name=template_name,
            status="pending",
        )

        try:
            self.db.add(playbook_record)
            self.db.commit()
            self.db.refresh(playbook_record)
            logger.info("Step 8 - SentinelPlaybook persisted: id=%s, playbook_id=%s",

                        playbook_record.id, playbook_id)
            
            # ── Step 8b: Trigger background LLM narrative generation ─────
            # Offloads LLM generation asynchronously using FastAPI BackgroundTasks
            # (or thread/event loop fallbacks) to prevent database write connection locks.
            try:
                self.trigger_llm_narrative(playbook_record.id, background_tasks)
            except Exception as llm_exc:
                logger.warning(
                    "Step 8b - Failed to trigger LLM narrative summary: %s",
                    llm_exc,
                )
        except Exception as exc:
            self.db.rollback()
            logger.error("Failed to persist SentinelPlaybook: %s", exc)
            raise

        # ΓöÇΓöÇ Step 9: Store detected_signatures in PacketLog ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        sigs_stored = self._store_signatures(matched_logs, signature_names)
        logger.info("Step 9 - Stored signatures on %d PacketLog rows", sigs_stored)

        logger.info("SentinelService.generate_playbook() - COMPLETE")
        logger.info("=" * 60)


        # ΓöÇΓöÇ Attach result_dict for convenience ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        playbook_record.result_dict = {
            "playbook_id": playbook_id,
            "campaign_id": campaign_id,
            "service_type": service_type,
            "attack_type": attack_type,
            "protocol": protocol_str,
            "technique": {
                "id": primary_technique.get("technique_id"),
                "name": primary_technique.get("technique_name"),
                "tactic": primary_technique.get("tactic"),
                "url": primary_technique.get("url"),
                "severity": primary_technique.get("severity"),
            },
            "snort_rule": snort_rule,
            "sigma_rule": sigma_rule,
            "stix_bundle_json": stix_json,
            "playbook_name": playbook_name,
            "playbook_content": playbook_content,
            "template_name": template_name,
            "threat_score": threat_score,
            "confidence_score": confidence_score,
            "severity": confidence_severity,
            "confidence_breakdown": confidence_result.breakdown,
            "ioc_threat_level": ioc_threat_level,
            "ioc_count": len(ioc_rows),
            "matched_logs_count": len(matched_logs),
            "signatures_stored_count": sigs_stored,
            "detected_signatures": signature_names,
            "db_record_id": playbook_record.id,
        }

        # Store in seen campaigns to prevent duplicates
        if campaign_id != "CAMP-UNKNOWN":
            self.__class__._seen_campaigns[campaign_id] = playbook_record

        return playbook_record

    def trigger_llm_narrative(
        self,
        playbook_id: int,
        background_tasks: Optional[BackgroundTasks] = None
    ) -> None:
        """Trigger background LLM narrative generation.

        Uses FastAPI BackgroundTasks if provided, otherwise schedules via event
        loop executor or a daemon thread to prevent database write connection locks.
        """
        if background_tasks is not None:
            background_tasks.add_task(_run_llm_narrative_bg, playbook_id)
            logger.info(
                "Scheduled LLM narrative generation via FastAPI BackgroundTasks "
                "for playbook %d.", playbook_id
            )
        else:
            # Fallback: schedule asynchronously via event loop or background thread
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    loop.run_in_executor(None, _run_llm_narrative_bg, playbook_id)
                    logger.info(
                        "Scheduled LLM narrative generation in running event loop "
                        "executor for playbook %d.", playbook_id
                    )
                    return
            except RuntimeError:
                pass

            def _run_in_thread() -> None:
                _run_llm_narrative_bg(playbook_id)

            threading.Thread(target=_run_in_thread, daemon=True).start()
            logger.info(
                "Started background thread for LLM narrative generation "
                "for playbook %d.", playbook_id
            )
