"""
sentinel/playbook_generator.py
-------------------------------
Dynamic incident-response playbook generation using Jinja2 templates.

The :class:`PlaybookGenerator` class configures a Jinja2 ``Environment``
backed by a ``FileSystemLoader`` that points at ``sentinel/templates/``
(resolved relative to *this* source file via ``os.path.dirname(__file__)``).

Calling :meth:`~PlaybookGenerator.generate` with a context dictionary
selects the correct template based on the ``attack_pattern`` key and
returns the fully-rendered Markdown (or YAML) string ready for
downstream automation systems (SOAR, SDN controllers, ticketing, etc.).

Supported attack patterns
~~~~~~~~~~~~~~~~~~~~~~~~~

**Markdown playbooks** (primary – ``.md.j2``):

+-------------------------------------+-------------------------------+
| Pattern keyword(s)                  | Template selected             |
+=====================================+===============================+
| brute_force / brute-force /         | brute_force.md.j2             |
| failed_login / ssh_brute            |                               |
+-------------------------------------+-------------------------------+
| sqli / sql_injection / sqli_attempt | sqli_attempt.md.j2            |
+-------------------------------------+-------------------------------+
| port_scan / port-scan / scan /      | port_scan.md.j2               |
| recon / reconnaissance              |                               |
+-------------------------------------+-------------------------------+
| data_exfil / exfiltration / dlp /   | data_exfiltration.md.j2       |
| data_theft                          |                               |
+-------------------------------------+-------------------------------+
| *anything else*                     | base_playbook.md.j2           |
+-------------------------------------+-------------------------------+

**Legacy YAML playbooks** (``format="yaml"``):

+-------------------------------------+-------------------------------+
| brute_force / brute-force /         | brute_force_response.yaml.j2  |
| failed_login                        |                               |
+-------------------------------------+-------------------------------+
| port_scan / port-scan / scan        | port_scan_response.yaml.j2    |
+-------------------------------------+-------------------------------+
| credential_reuse / honeytoken       | credential_reuse_response     |
|                                     | .yaml.j2                      |
+-------------------------------------+-------------------------------+
| distributed_attack / distributed    | distributed_attack_response   |
|                                     | .yaml.j2                      |
+-------------------------------------+-------------------------------+
| *anything else*                     | ``{pattern}_response.yaml.j2``|
+-------------------------------------+-------------------------------+

Usage example
~~~~~~~~~~~~~
::

    from sentinel.playbook_generator import PlaybookGenerator

    gen = PlaybookGenerator()

    # Markdown playbook (default format)
    playbook_md = gen.generate({
        "attack_pattern": "brute_force",
        "source_ip": "192.168.1.100",
        "severity": "CRITICAL",
        "failed_logins_threshold": 30,
    })
    print(playbook_md)

    # Legacy YAML playbook
    playbook_yaml = gen.generate({
        "attack_pattern": "brute_force",
        "source_ip": "192.168.1.100",
    }, format="yaml")
"""

import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------
__version__ = "2.0.0"

# ---------------------------------------------------------------------------
# Module-level logger – inherits configuration from the root logger so that
# the calling application controls verbosity via standard logging setup.
# ---------------------------------------------------------------------------
logger = logging.getLogger("sentinel.playbook_generator")


class PlaybookGenerator:
    """Dynamically generate incident-response playbooks from Jinja2 templates.

    On instantiation a Jinja2 :class:`~jinja2.Environment` is configured
    with a :class:`~jinja2.FileSystemLoader` pointing at the
    ``sentinel/templates/`` directory (or a custom path supplied by the
    caller).  The :meth:`generate` method selects the appropriate template
    for a given ``attack_pattern`` and renders it with the provided context.

    Parameters
    ----------
    templates_dir:
        Absolute or relative path to the directory that contains the
        template files.  When *None* (default) the loader resolves
        ``templates/`` relative to this source file, i.e.
        ``sentinel/templates/``.

    Attributes
    ----------
    templates_dir : str
        Resolved, absolute path to the templates directory.
    loader : jinja2.FileSystemLoader
        Jinja2 loader bound to :attr:`templates_dir`.
    env : jinja2.Environment
        Configured Jinja2 environment (auto-escape disabled; safe for
        Markdown and YAML output).
    """

    # ------------------------------------------------------------------
    # Markdown (.md.j2) pattern → template mapping.
    # Keys are tuples of substrings matched case-insensitively against the
    # normalised attack_pattern value.  Order matters – first match wins.
    # ------------------------------------------------------------------
    _MD_PATTERN_MAP: List[tuple] = [
        (
            ("brute_force", "brute-force", "failed_login", "ssh_brute"),
            "brute_force.md.j2",
        ),
        (
            ("sqli", "sql_injection", "sqli_attempt", "sql-injection"),
            "sqli_attempt.md.j2",
        ),
        (
            ("port_scan", "port-scan", "scan", "recon", "reconnaissance"),
            "port_scan.md.j2",
        ),
        (
            ("data_exfil", "exfiltration", "dlp", "data_theft"),
            "data_exfiltration.md.j2",
        ),
    ]

    # ------------------------------------------------------------------
    # Legacy YAML (.yaml.j2) pattern → template mapping (backward compat).
    # ------------------------------------------------------------------
    _YAML_PATTERN_MAP: List[tuple] = [
        (("brute_force", "brute-force", "failed_login"), "brute_force_response.yaml.j2"),
        (("port_scan", "port-scan", "scan"),              "port_scan_response.yaml.j2"),
        (("credential_reuse", "credential-reuse", "honeytoken"), "credential_reuse_response.yaml.j2"),
        (("distributed_attack", "distributed-attack", "distributed"), "distributed_attack_response.yaml.j2"),
    ]

    # Kept for backward compatibility — points at the legacy YAML map.
    _PATTERN_MAP: List[tuple] = _YAML_PATTERN_MAP

    # ------------------------------------------------------------------
    # Default ATT&CK technique mappings per attack pattern.
    # Used to auto-populate ``attack_techniques`` when the caller does
    # not supply them.
    # ------------------------------------------------------------------
    _DEFAULT_ATTACK_TECHNIQUES: Dict[str, List[Dict[str, str]]] = {
        "brute_force": [
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
             "subtechnique": "T1110.001 – Password Guessing",
             "description": "Adversary attempts to gain access by systematically guessing passwords."},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion, Persistence",
             "subtechnique": "—",
             "description": "Adversary may use compromised credentials to maintain access."},
            {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement",
             "subtechnique": "T1021.004 – SSH",
             "description": "Brute-forced credentials may be used to move laterally via SSH."},
        ],
        "sqli_attempt": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
             "subtechnique": "—",
             "description": "Adversary exploits SQL injection in a web application."},
            {"id": "T1005", "name": "Data from Local System", "tactic": "Collection",
             "subtechnique": "—",
             "description": "Adversary extracts data from the compromised database."},
            {"id": "T1565", "name": "Data Manipulation", "tactic": "Impact",
             "subtechnique": "T1565.001 – Stored Data Manipulation",
             "description": "Adversary may alter or destroy database records."},
        ],
        "port_scan": [
            {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance",
             "subtechnique": "T1595.001 – Scanning IP Blocks",
             "description": "Adversary probes the network to discover live hosts and open services."},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
             "subtechnique": "—",
             "description": "Adversary enumerates available services on remote hosts."},
            {"id": "T1590", "name": "Gather Victim Network Information", "tactic": "Reconnaissance",
             "subtechnique": "T1590.004 – Network Topology",
             "description": "Port scan results reveal network topology and segmentation gaps."},
        ],
        "data_exfiltration": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
             "subtechnique": "—",
             "description": "Data sent out via an established C2 channel."},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
             "subtechnique": "T1048.003 – Unencrypted/Obfuscated",
             "description": "Data exfiltrated over a non-standard protocol."},
            {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration",
             "subtechnique": "T1567.002 – Cloud Storage",
             "description": "Data uploaded to cloud storage service."},
            {"id": "T1074", "name": "Data Staged", "tactic": "Collection",
             "subtechnique": "T1074.001 – Local Data Staging",
             "description": "Data collected and archived locally before exfiltration."},
        ],
    }

    # ------------------------------------------------------------------
    # Default containment step summaries per attack pattern.
    # These are used when the caller does not supply ``containment_steps``.
    # ------------------------------------------------------------------
    _DEFAULT_CONTAINMENT: Dict[str, List[str]] = {
        "brute_force": [
            "Block attacker IP at perimeter firewall",
            "Enable tarpit / rate-limit on targeted SSH port",
            "Rotate SSH keys on all affected hosts",
            "Review auth logs for successful compromises",
            "Verify account lockout thresholds",
            "Enforce password policy compliance",
            "Enable MFA on all SSH endpoints",
        ],
        "sqli_attempt": [
            "Block attacker IP at WAF and perimeter",
            "Capture HTTP request logs for forensic analysis",
            "Kill suspicious database sessions",
            "Switch WAF to prevention/block mode",
            "Audit input validation on affected endpoints",
            "Review database binary logs for data manipulation",
            "Rotate database credentials",
        ],
        "port_scan": [
            "Capture scanner traffic (tcpdump)",
            "Rate-limit then block scanner IP",
            "Deploy deception honeypots in scanned subnet",
            "Review network segmentation and inter-VLAN ACLs",
            "Audit exposed services against CMDB baseline",
            "Update IDS/IPS signatures for scanner fingerprint",
            "Harden service banners to reduce intelligence leakage",
        ],
        "data_exfiltration": [
            "Capture live memory from source host (do NOT reboot)",
            "Isolate source host from network",
            "Block destination IP/domain at perimeter",
            "Pull DLP alert logs and identify policy gaps",
            "Switch DLP to block mode",
            "Verify file integrity with AIDE/Tripwire baseline",
            "Reconstruct exfiltration timeline from NetFlow",
            "Classify exfiltrated data and assess breach notification",
        ],
    }

    def __init__(self, templates_dir: Optional[str] = None) -> None:
        if templates_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            templates_dir = os.path.join(current_dir, "templates")

        self.templates_dir: str = os.path.abspath(templates_dir)
        logger.info("Initializing PlaybookGenerator | templates_dir=%s", self.templates_dir)

        # Configure Jinja2 environment with FileSystemLoader
        self.loader: FileSystemLoader = FileSystemLoader(self.templates_dir)
        self.env: Environment = Environment(
            loader=self.loader,
            autoescape=False,       # Markdown/YAML output – HTML escaping must be off
            trim_blocks=True,       # Strip first newline after a block tag
            lstrip_blocks=True,     # Strip leading whitespace from block tags
            keep_trailing_newline=True,
        )

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def list_templates(self, extension: Optional[str] = None) -> List[str]:
        """Return the names of all available templates, optionally filtered.

        Parameters
        ----------
        extension:
            File extension filter (e.g. ``".yaml.j2"``, ``".md.j2"``).
            When *None* (default), returns ``.yaml.j2`` templates for
            backward compatibility.

        Returns
        -------
        list[str]
            Sorted list of template filenames found in :attr:`templates_dir`.

        Example
        -------
        ::

            gen = PlaybookGenerator()
            print(gen.list_templates())          # .yaml.j2 only
            print(gen.list_templates(".md.j2"))   # .md.j2 only
        """
        if extension is None:
            extension = ".yaml.j2"
        templates = sorted(
            f for f in self.env.list_templates()
            if f.endswith(extension)
        )
        logger.debug("Available templates (ext=%s): %s", extension, templates)
        return templates

    def validate_context(self, context_data: Dict[str, Any]) -> None:
        """Validate that *context_data* contains the mandatory ``attack_pattern`` key.

        Parameters
        ----------
        context_data:
            The context dictionary that will be passed to :meth:`generate`.

        Raises
        ------
        ValueError
            If ``attack_pattern`` is missing or evaluates to an empty string.
        TypeError
            If *context_data* is not a dictionary.
        """
        if not isinstance(context_data, dict):
            raise TypeError(
                f"context_data must be a dict, got {type(context_data).__name__!r}"
            )
        attack_pattern = context_data.get("attack_pattern")
        if not attack_pattern:
            raise ValueError(
                "context_data must contain an 'attack_pattern' key with a non-empty value."
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _normalise_pattern(self, attack_pattern: str) -> str:
        """Normalise *attack_pattern* to a consistent format.

        Converts to lowercase, strips whitespace, replaces hyphens and
        spaces with underscores.

        Parameters
        ----------
        attack_pattern:
            Raw attack-pattern string from ``context_data``.

        Returns
        -------
        str
            Normalised pattern string.
        """
        return attack_pattern.lower().strip().replace("-", "_").replace(" ", "_")

    def _select_template(self, attack_pattern: str, format: str = "yaml") -> str:
        """Select the template filename for *attack_pattern*.

        The lookup is case-insensitive.  The first entry in the relevant
        pattern map whose keyword list contains a substring that appears
        in *attack_pattern* is used.

        Parameters
        ----------
        attack_pattern:
            Raw attack-pattern string from ``context_data``.
        format:
            ``"markdown"`` for ``.md.j2`` templates (default for
            :meth:`generate`), ``"yaml"`` for legacy ``.yaml.j2`` templates.

        Returns
        -------
        str
            Template filename (not a full path).

        Raises
        ------
        ValueError
            If *attack_pattern* is empty or *None*.
        """
        if not attack_pattern:
            raise ValueError("attack_pattern must be a non-empty string.")

        pattern = attack_pattern.lower().strip()

        if format == "markdown":
            pattern_map = self._MD_PATTERN_MAP
            fallback_template = "base_playbook.md.j2"
        else:
            pattern_map = self._YAML_PATTERN_MAP
            fallback_template = None  # Will be computed below

        for keywords, template_name in pattern_map:
            if any(kw in pattern for kw in keywords):
                logger.debug(
                    "Pattern %r matched keywords %r → template %r (format=%s)",
                    attack_pattern, keywords, template_name, format,
                )
                return template_name

        if format == "markdown":
            logger.info(
                "No specific Markdown template for %r – using base_playbook.md.j2",
                attack_pattern,
            )
            return fallback_template
        else:
            # Legacy YAML fallback – lets callers register custom templates at runtime
            fallback = f"{pattern}_response.yaml.j2"
            logger.warning(
                "Unknown attack pattern %r – falling back to %r. "
                "Add a template or extend _PATTERN_MAP if this is a new pattern.",
                attack_pattern, fallback,
            )
            return fallback

    def _resolve_canonical_pattern(self, attack_pattern: str) -> str:
        """Map user-supplied *attack_pattern* to a canonical internal key.

        This canonical key is used to look up default ATT&CK techniques,
        containment steps, and artifact references.

        Parameters
        ----------
        attack_pattern:
            Raw or normalised pattern string.

        Returns
        -------
        str
            One of ``"brute_force"``, ``"sqli_attempt"``, ``"port_scan"``,
            ``"data_exfiltration"``, or ``"unknown"``.
        """
        p = attack_pattern.lower().strip()
        if any(kw in p for kw in ("brute_force", "brute-force", "failed_login", "ssh_brute")):
            return "brute_force"
        if any(kw in p for kw in ("sqli", "sql_injection", "sqli_attempt", "sql-injection")):
            return "sqli_attempt"
        if any(kw in p for kw in ("port_scan", "port-scan", "scan", "recon", "reconnaissance")):
            return "port_scan"
        if any(kw in p for kw in ("data_exfil", "exfiltration", "dlp", "data_theft")):
            return "data_exfiltration"
        return "unknown"

    def _build_enriched_context(
        self,
        context_data: Dict[str, Any],
        canonical_pattern: str,
    ) -> Dict[str, Any]:
        """Build the enriched template context for Markdown playbook rendering.

        This method auto-populates all required Jinja2 variables that are
        not already supplied by the caller:

        - ``generated_at`` – ISO-8601 UTC timestamp
        - ``generator_version`` – current module version
        - ``attack_techniques`` – default MITRE ATT&CK technique list
        - ``containment_steps`` – default ordered containment actions
        - Sensible defaults for severity, classification, owner, etc.

        Parameters
        ----------
        context_data:
            Raw context dict from the caller.
        canonical_pattern:
            One of the canonical pattern keys (e.g. ``"brute_force"``).

        Returns
        -------
        dict[str, Any]
            A new dictionary (caller's dict is not mutated) with enriched
            context variables ready for template rendering.
        """
        ctx = dict(context_data)  # shallow copy – don't mutate the caller's dict

        # ── 1. Timestamps ─────────────────────────────────────────────
        ctx.setdefault("generated_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        ctx.setdefault("generator_version", __version__)
        ctx.setdefault("detection_time", ctx["generated_at"])

        # ── 2. Playbook metadata ──────────────────────────────────────
        ctx.setdefault("severity", "HIGH")
        ctx.setdefault("classification", "TLP:AMBER")
        ctx.setdefault("owner", "Security Operations Centre (SOC)")
        ctx.setdefault("status", "ACTIVE")
        ctx.setdefault("version", "1.0.0")

        # ── 3. IOC enrichment ─────────────────────────────────────────
        # Build a structured IOC list from flat context if not provided.
        if "iocs" not in ctx:
            source_ip = ctx.get("source_ip")
            if source_ip:
                ctx["iocs"] = [{
                    "ip": source_ip,
                    "ports": ctx.get("target_port", ctx.get("ssh_port", "N/A")),
                    "protocol": ctx.get("protocol", "TCP"),
                    "hit_count": ctx.get("hit_count", ctx.get("event_count", 1)),
                    "threat_intel": ctx.get("threat_intel_result", "❓ Pending lookup"),
                    "first_seen": ctx.get("first_seen", ctx.get("detection_time", "N/A")),
                    "last_seen": ctx.get("last_seen", ctx.get("generated_at", "N/A")),
                }]

        # ── 4. ATT&CK technique enrichment ────────────────────────────
        if "attack_techniques" not in ctx:
            ctx["attack_techniques"] = self._DEFAULT_ATTACK_TECHNIQUES.get(
                canonical_pattern, []
            )

        # ── 5. Containment step summaries ─────────────────────────────
        if "containment_steps" not in ctx:
            ctx["containment_steps"] = self._DEFAULT_CONTAINMENT.get(
                canonical_pattern, [
                    "Investigate the alert and gather IOCs",
                    "Isolate affected assets",
                    "Block attacker IPs at perimeter",
                    "Escalate to incident commander",
                ]
            )

        # ── 6. Event / count defaults ─────────────────────────────────
        ctx.setdefault("event_count", ctx.get("hit_count", 0))

        # ── 7. Pattern-specific enrichment ────────────────────────────
        if canonical_pattern == "brute_force":
            ctx.setdefault("ssh_port", 22)
            ctx.setdefault("failed_logins_threshold", 10)
            ctx.setdefault("block_duration", "3600")
            ctx.setdefault("tarpit_delay_ms", 5000)
            ctx.setdefault("alert_level", ctx.get("severity", "HIGH"))
            ctx.setdefault("lockout_policy_threshold", 5)
            ctx.setdefault("min_password_length", 16)
            ctx.setdefault("audit_period_hours", 48)
            ctx.setdefault("ticket_system", "Jira")
            ctx.setdefault("ticket_project", "SEC")

        elif canonical_pattern == "sqli_attempt":
            ctx.setdefault("target_url", ctx.get("target_endpoint", "N/A"))
            ctx.setdefault("db_engine", "MySQL")
            ctx.setdefault("db_host", "N/A")
            ctx.setdefault("db_name", "N/A")
            ctx.setdefault("waf_vendor", "None / Unknown")
            ctx.setdefault("waf_mode", "detection")
            ctx.setdefault("http_method", "GET")
            ctx.setdefault("block_duration", "3600")
            ctx.setdefault("alert_level", ctx.get("severity", "HIGH"))
            ctx.setdefault("audit_period_hours", 48)
            ctx.setdefault("ticket_system", "Jira")
            ctx.setdefault("ticket_project", "SEC")

        elif canonical_pattern == "port_scan":
            ctx.setdefault("scan_type", "SYN")
            ctx.setdefault("port_count", 0)
            ctx.setdefault("port_count_threshold", 50)
            ctx.setdefault("block_duration", "3600")
            ctx.setdefault("honeypot_count", 3)
            ctx.setdefault("honeypot_type", "deception_mesh")
            ctx.setdefault("deception_mode", "aggressive_deception")
            ctx.setdefault("capture_duration", "300s")
            ctx.setdefault("sdn_enabled", True)
            ctx.setdefault("alert_level", ctx.get("severity", "HIGH"))
            ctx.setdefault("audit_period_hours", 48)
            ctx.setdefault("ticket_system", "Jira")
            ctx.setdefault("ticket_project", "SEC")

        elif canonical_pattern == "data_exfiltration":
            ctx.setdefault("exfil_vector", "https")
            ctx.setdefault("data_classification", "CONFIDENTIAL")
            ctx.setdefault("dlp_vendor", "None / Unknown")
            ctx.setdefault("dlp_mode", "monitor")
            ctx.setdefault("exfil_bytes", 0)
            ctx.setdefault("exfil_bytes_hr", "Unknown")
            ctx.setdefault("baseline_bytes_per_day", "Unknown")
            ctx.setdefault("breach_notif_required", False)
            ctx.setdefault("legal_hold_required", False)
            ctx.setdefault("insider_threat", False)
            ctx.setdefault("c2_suspected", False)
            ctx.setdefault("alert_level", ctx.get("severity", "CRITICAL"))
            ctx.setdefault("audit_period_hours", 72)
            ctx.setdefault("ticket_system", "Jira")
            ctx.setdefault("ticket_project", "SEC")
            # Override default severity – data exfil defaults to CRITICAL
            if "severity" not in context_data:
                ctx["severity"] = "CRITICAL"
            if "classification" not in context_data:
                ctx["classification"] = "TLP:RED"

        logger.debug(
            "Enriched context for %r: %d keys (canonical_pattern=%s)",
            ctx.get("attack_pattern"), len(ctx), canonical_pattern,
        )
        return ctx

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def generate(self, context_data: Dict[str, Any], format: str = "markdown") -> str:
        """Generate a playbook for the given *context_data*.

        This is the primary public interface of the class.  It:

        1. Validates *context_data* via :meth:`validate_context`.
        2. Selects the appropriate Jinja2 template via :meth:`_select_template`.
        3. Enriches the context with timestamps, IOCs, ATT&CK data,
           containment defaults, and artifact references (Markdown only).
        4. Loads and renders the template, returning the result.

        Parameters
        ----------
        context_data:
            A dictionary of rendering variables.  **Must** include
            ``attack_pattern`` (``str``).  All other keys are forwarded to
            the Jinja2 template as context variables.

        format:
            Output format – ``"markdown"`` (default) renders ``.md.j2``
            playbooks with full enrichment.  ``"yaml"`` renders the legacy
            ``.yaml.j2`` templates without enrichment (backward compatible).

        Returns
        -------
        str
            Rendered playbook as a string (Markdown or YAML).

        Raises
        ------
        ValueError
            If ``attack_pattern`` is missing from *context_data* or
            *format* is not ``"markdown"`` or ``"yaml"``.
        TypeError
            If *context_data* is not a dictionary.
        FileNotFoundError
            If no matching template file is found in :attr:`templates_dir`.
        jinja2.TemplateError
            If Jinja2 encounters a rendering error.

        Example
        -------
        ::

            gen = PlaybookGenerator()

            # Markdown playbook (default)
            md = gen.generate({
                "attack_pattern": "brute_force",
                "source_ip": "192.168.1.100",
                "severity": "CRITICAL",
            })

            # Legacy YAML playbook
            yml = gen.generate({
                "attack_pattern": "brute_force",
                "source_ip": "192.168.1.100",
            }, format="yaml")
        """
        if format not in ("markdown", "yaml"):
            raise ValueError(
                f"format must be 'markdown' or 'yaml', got {format!r}"
            )

        # --- Step 1: validate input -------------------------------------
        self.validate_context(context_data)
        attack_pattern: str = context_data["attack_pattern"]

        # --- Step 2: select template ------------------------------------
        template_name = self._select_template(attack_pattern, format=format)
        logger.info(
            "Rendering playbook | attack_pattern=%r template=%r format=%s",
            attack_pattern, template_name, format,
        )

        # --- Step 3: enrich context (Markdown only) ---------------------
        if format == "markdown":
            canonical = self._resolve_canonical_pattern(attack_pattern)
            render_ctx = self._build_enriched_context(context_data, canonical)
        else:
            # Legacy YAML – pass through as-is (backward compat)
            render_ctx = dict(context_data)

        # --- Step 4: load template --------------------------------------
        try:
            template = self.env.get_template(template_name)
        except TemplateNotFound as exc:
            logger.error("Template not found: %s", template_name)
            raise FileNotFoundError(
                f"Template '{template_name}' not found for attack pattern '{attack_pattern}'. "
                f"Available templates: {self.list_templates('.md.j2') + self.list_templates('.yaml.j2')}"
            ) from exc

        # --- Step 5: render and return ----------------------------------
        try:
            rendered: str = template.render(**render_ctx)
            logger.debug("Playbook rendered successfully (%d chars, format=%s).", len(rendered), format)
            return rendered
        except Exception as exc:
            logger.error("Failed to render template %r: %s", template_name, exc)
            raise

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"{self.__class__.__name__}("
            f"templates_dir={self.templates_dir!r}, "
            f"md_templates={self.list_templates('.md.j2')!r}, "
            f"yaml_templates={self.list_templates('.yaml.j2')!r})"
        )
