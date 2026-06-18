"""
sentinel/playbook_generator.py
-------------------------------
Dynamic incident-response playbook generation using Jinja2 templates.

The :class:`PlaybookGenerator` class configures a Jinja2 ``Environment``
backed by a ``FileSystemLoader`` that points at ``sentinel/templates/``.
Calling :meth:`~PlaybookGenerator.generate` with a context dictionary
selects the correct ``.yaml.j2`` template based on the ``attack_pattern``
key and returns the fully-rendered YAML string ready for downstream
automation systems (SOAR, SDN controllers, etc.).

Supported attack patterns
~~~~~~~~~~~~~~~~~~~~~~~~~
+------------------------+--------------------------------------+
| Pattern keyword(s)     | Template selected                    |
+========================+======================================+
| brute_force / brute-force / failed_login | brute_force_response.yaml.j2 |
+------------------------+--------------------------------------+
| port_scan / port-scan / scan            | port_scan_response.yaml.j2   |
+------------------------+--------------------------------------+
| credential_reuse / credential-reuse / honeytoken | credential_reuse_response.yaml.j2 |
+------------------------+--------------------------------------+
| distributed_attack / distributed-attack / distributed | distributed_attack_response.yaml.j2 |
+------------------------+--------------------------------------+
| *anything else*        | ``{pattern}_response.yaml.j2``       |
+------------------------+--------------------------------------+

Usage example
~~~~~~~~~~~~~
::

    from sentinel.playbook_generator import PlaybookGenerator

    gen = PlaybookGenerator()
    playbook_yaml = gen.generate({
        "attack_pattern": "brute_force",
        "source_ip": "192.168.1.100",
        "failed_logins_threshold": 30,
        "alert_level": "CRITICAL",
    })
    print(playbook_yaml)
"""

import os
import logging
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

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
        ``*.yaml.j2`` template files.  When *None* (default) the loader
        resolves ``templates/`` relative to this source file, i.e.
        ``sentinel/templates/``.

    Attributes
    ----------
    templates_dir : str
        Resolved, absolute path to the templates directory.
    loader : jinja2.FileSystemLoader
        Jinja2 loader bound to :attr:`templates_dir`.
    env : jinja2.Environment
        Configured Jinja2 environment (auto-escape disabled; safe for YAML).
    """

    # ------------------------------------------------------------------
    # Pattern → template filename mapping.
    # Keys are *substrings* matched case-insensitively against the
    # normalised attack_pattern value.  Order matters – first match wins.
    # ------------------------------------------------------------------
    _PATTERN_MAP: List[tuple] = [
        (("brute_force", "brute-force", "failed_login"), "brute_force_response.yaml.j2"),
        (("port_scan", "port-scan", "scan"),              "port_scan_response.yaml.j2"),
        (("credential_reuse", "credential-reuse", "honeytoken"), "credential_reuse_response.yaml.j2"),
        (("distributed_attack", "distributed-attack", "distributed"), "distributed_attack_response.yaml.j2"),
    ]

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
            autoescape=False,       # YAML output – HTML escaping must be off
            trim_blocks=True,       # Strip first newline after a block tag
            lstrip_blocks=True,     # Strip leading whitespace from block tags
            keep_trailing_newline=True,
        )

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def list_templates(self) -> List[str]:
        """Return the names of all available ``.yaml.j2`` templates.

        Returns
        -------
        list[str]
            Sorted list of template filenames found in :attr:`templates_dir`.

        Example
        -------
        ::

            gen = PlaybookGenerator()
            print(gen.list_templates())
            # ['brute_force_response.yaml.j2', 'port_scan_response.yaml.j2', ...]
        """
        templates = sorted(
            f for f in self.env.list_templates()
            if f.endswith(".yaml.j2")
        )
        logger.debug("Available templates: %s", templates)
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

    def _select_template(self, attack_pattern: str) -> str:
        """Select the ``.yaml.j2`` template filename for *attack_pattern*.

        The lookup is case-insensitive.  The first entry in
        :attr:`_PATTERN_MAP` whose keyword list contains a substring that
        appears in *attack_pattern* is used.  Unknown patterns fall back to
        ``{normalised_pattern}_response.yaml.j2``.

        Parameters
        ----------
        attack_pattern:
            Raw attack-pattern string from ``context_data``.

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

        for keywords, template_name in self._PATTERN_MAP:
            if any(kw in pattern for kw in keywords):
                logger.debug(
                    "Pattern %r matched keywords %r → template %r",
                    attack_pattern, keywords, template_name,
                )
                return template_name

        # Graceful fallback – lets callers register custom templates at runtime
        fallback = f"{pattern}_response.yaml.j2"
        logger.warning(
            "Unknown attack pattern %r – falling back to %r. "
            "Add a template or extend _PATTERN_MAP if this is a new pattern.",
            attack_pattern, fallback,
        )
        return fallback

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def generate(self, context_data: Dict[str, Any]) -> str:
        """Generate a playbook YAML string for the given *context_data*.

        This is the primary public interface of the class.  It:

        1. Validates *context_data* via :meth:`validate_context`.
        2. Selects the appropriate Jinja2 template via :meth:`_select_template`.
        3. Loads and renders the template, returning the resulting YAML string.

        Parameters
        ----------
        context_data:
            A dictionary of rendering variables.  **Must** include
            ``attack_pattern`` (``str``).  All other keys are forwarded to
            the Jinja2 template as context variables.

        Returns
        -------
        str
            Rendered YAML playbook as a string.

        Raises
        ------
        ValueError
            If ``attack_pattern`` is missing from *context_data*.
        TypeError
            If *context_data* is not a dictionary.
        FileNotFoundError
            If no matching template file is found in :attr:`templates_dir`.
        jinja2.TemplateError
            If Jinja2 encounters a rendering error (e.g. invalid template syntax).

        Example
        -------
        ::

            gen = PlaybookGenerator()
            yaml_str = gen.generate({
                "attack_pattern": "port_scan",
                "source_ip": "10.0.0.5",
                "port_count_threshold": 100,
            })
        """
        # --- Step 1: validate input -------------------------------------
        self.validate_context(context_data)
        attack_pattern: str = context_data["attack_pattern"]

        # --- Step 2: select template ------------------------------------
        template_name = self._select_template(attack_pattern)
        logger.info(
            "Rendering playbook | attack_pattern=%r template=%r",
            attack_pattern, template_name,
        )

        # --- Step 3: load template --------------------------------------
        try:
            template = self.env.get_template(template_name)
        except TemplateNotFound as exc:
            logger.error("Template not found: %s", template_name)
            raise FileNotFoundError(
                f"Template '{template_name}' not found for attack pattern '{attack_pattern}'. "
                f"Available templates: {self.list_templates()}"
            ) from exc

        # --- Step 4: render and return ----------------------------------
        try:
            rendered_yaml: str = template.render(**context_data)
            logger.debug("Playbook rendered successfully (%d chars).", len(rendered_yaml))
            return rendered_yaml
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
            f"templates={self.list_templates()!r})"
        )
