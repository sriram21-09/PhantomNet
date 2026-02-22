"""
client.py — Honeypot Coordinator Client
Week9-Day1 | PhantomNet Project

A reusable CoordinatorClient class that any PhantomNet honeypot can import
to participate in the distributed mesh coordination system.

Usage Example:
    from honeypots.client import CoordinatorClient
    import asyncio

    async def main():
        client = CoordinatorClient(
            node_id="ssh-node-1",
            host="127.0.0.1",
            port=2222,
            protocol="SSH",
        )
        await client.register()
        await client.report_event(src_ip="10.0.0.5", details={"username": "root"})
        threats = await client.get_threats()
        print(threats)
        await client.deregister()

    asyncio.run(main())
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

try:
    import httpx
except ImportError as exc:
    raise ImportError(
        "httpx is required for CoordinatorClient. Install it with: pip install httpx"
    ) from exc

logger = logging.getLogger("honeypot.client")

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_COORDINATOR_URL = "http://127.0.0.1:8001"
DEFAULT_HEARTBEAT_INTERVAL = 30       # seconds
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BASE_DELAY = 1.0        # seconds (doubles on each retry)
DEFAULT_TIMEOUT = 10.0               # HTTP request timeout in seconds


# ---------------------------------------------------------------------------
# CoordinatorClient
# ---------------------------------------------------------------------------

class CoordinatorClient:
    """
    Client library for honeypot nodes wishing to join the PhantomNet
    coordination mesh.

    Features:
    - Auto-retry with exponential backoff (configurable)
    - Async-first API using httpx.AsyncClient
    - Background heartbeat loop
    - Shared threat intelligence polling
    - Graceful deregistration on shutdown

    Parameters
    ----------
    node_id : str
        Unique identifier for this honeypot node (e.g. "ssh-node-1").
    host : str
        The host/IP this honeypot listens on (reported to coordinator).
    port : int
        The port this honeypot listens on.
    protocol : str
        Protocol served by this honeypot: SSH | HTTP | FTP | SMTP | etc.
    coordinator_url : str
        Base URL of the coordinator service.
    version : str
        Client/honeypot version string.
    metadata : dict, optional
        Any extra info about this node.
    heartbeat_interval : int
        How often (in seconds) to send heartbeats.
    max_retries : int
        Number of retry attempts for failed requests.
    timeout : float
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        node_id: str,
        host: str,
        port: int,
        protocol: str,
        coordinator_url: str = DEFAULT_COORDINATOR_URL,
        version: str = "1.0.0",
        metadata: Optional[Dict[str, Any]] = None,
        heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.node_id = node_id
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
        self.coordinator_url = coordinator_url.rstrip("/")
        self.version = version
        self.metadata = metadata or {}
        self.heartbeat_interval = heartbeat_interval
        self.max_retries = max_retries
        self.timeout = timeout

        # Internal state
        self._event_count: int = 0
        self._registered: bool = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._status: str = "active"

        # Shared HTTP client (reused across all requests for connection pooling)
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.coordinator_url,
                timeout=self.timeout,
                headers={"X-Node-Id": self.node_id, "Content-Type": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Retry wrapper
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Execute an HTTP request with exponential-backoff retry on failures.

        Returns the parsed JSON response on success.
        Raises httpx.HTTPError after all retries are exhausted.
        """
        client = await self._get_client()
        last_exc: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = await client.request(method, path, **kwargs)
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_exc = exc
                delay = DEFAULT_RETRY_BASE_DELAY * (2 ** (attempt - 1))
                logger.warning(
                    "[%s] Request %s %s failed (attempt %d/%d): %s. Retrying in %.1fs…",
                    self.node_id, method.upper(), path, attempt, self.max_retries, exc, delay,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(delay)

        logger.error("[%s] All %d retries exhausted for %s %s", self.node_id, self.max_retries, method, path)
        raise last_exc  # type: ignore[misc]

    # ------------------------------------------------------------------
    # Core coordination API
    # ------------------------------------------------------------------

    async def register(self) -> Dict[str, Any]:
        """
        Register this node with the coordinator.
        Must be called before any other coordination methods.

        Returns the coordinator's registration response.
        """
        payload = {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "version": self.version,
            "metadata": self.metadata,
        }
        result = await self._request("POST", "/register", json=payload)
        self._registered = True
        logger.info("[%s] Registered with coordinator at %s", self.node_id, self.coordinator_url)
        return result

    async def send_heartbeat(
        self,
        status: Optional[str] = None,
        cpu_percent: Optional[float] = None,
        memory_mb: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Send a heartbeat to signal this node is alive.

        Parameters
        ----------
        status : str, optional
            Override the current status (default uses internal _status).
        cpu_percent : float, optional
            Current CPU usage percentage.
        memory_mb : float, optional
            Current memory usage in MB.
        """
        payload: Dict[str, Any] = {
            "node_id": self.node_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": status or self._status,
            "event_count": self._event_count,
        }
        if cpu_percent is not None:
            payload["cpu_percent"] = cpu_percent
        if memory_mb is not None:
            payload["memory_mb"] = memory_mb

        result = await self._request("POST", "/heartbeat", json=payload)
        logger.debug("[%s] Heartbeat sent", self.node_id)
        return result

    async def report_event(
        self,
        src_ip: str,
        event_type: str = "connection",
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Report a captured honeypot interaction to the coordinator.

        Parameters
        ----------
        src_ip : str
            IP address of the connecting party.
        event_type : str
            One of: connection | login_attempt | command | scan
        src_port : int, optional
            Source port of the connection.
        dst_port : int, optional
            Destination port on the honeypot.
        details : dict, optional
            Protocol-specific event payload (usernames, commands, headers…).
        """
        payload: Dict[str, Any] = {
            "node_id": self.node_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "protocol": self.protocol,
            "event_type": event_type,
            "details": details or {},
        }
        if src_port is not None:
            payload["src_port"] = src_port
        if dst_port is not None:
            payload["dst_port"] = dst_port

        result = await self._request("POST", "/event", json=payload)
        self._event_count += 1
        return result

    async def report_alert(
        self,
        src_ip: str,
        description: str,
        severity: str = "HIGH",
        alert_type: str = "brute_force",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Report a high-severity alert to the coordinator.
        HIGH and CRITICAL alerts cause the coordinator to add src_ip to its blocklist.

        Parameters
        ----------
        src_ip : str
            Attacker IP address.
        description : str
            Human-readable alert summary.
        severity : str
            LOW | MEDIUM | HIGH | CRITICAL
        alert_type : str
            brute_force | scan | exploit | anomaly
        details : dict, optional
            Supporting evidence (failed attempts, payloads, etc.).
        """
        payload: Dict[str, Any] = {
            "node_id": self.node_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity.upper(),
            "src_ip": src_ip,
            "description": description,
            "alert_type": alert_type,
            "details": details or {},
        }
        result = await self._request("POST", "/alert", json=payload)
        logger.warning(
            "[%s] Alert reported [%s]: %s from %s",
            self.node_id, severity, description, src_ip,
        )
        return result

    async def get_threats(self) -> Dict[str, Any]:
        """
        Fetch the current shared threat intelligence from the coordinator.

        Returns a dict containing:
        - blocked_ips: List[str]
        - high_severity_ips: List[str]
        - recent_alerts: List[dict]
        - total_events: int
        - last_updated: str (ISO timestamp)
        """
        return await self._request("GET", "/threats")

    async def get_nodes(self, active_only: bool = False) -> Dict[str, Any]:
        """
        Get the list of registered honeypot nodes from the coordinator.

        Parameters
        ----------
        active_only : bool
            If True, returns only nodes with recent heartbeats.
        """
        params = {"active_only": "true" if active_only else "false"}
        return await self._request("GET", "/nodes", params=params)

    async def deregister(self, reason: str = "graceful_shutdown") -> Dict[str, Any]:
        """
        Gracefully remove this node from the mesh.
        Should be called in a shutdown handler.
        """
        payload = {"node_id": self.node_id, "reason": reason}
        result = await self._request("POST", "/deregister", json=payload)
        self._registered = False
        logger.info("[%s] Deregistered from coordinator", self.node_id)
        return result

    # ------------------------------------------------------------------
    # Background heartbeat loop
    # ------------------------------------------------------------------

    async def run_heartbeat_loop(
        self,
        interval: Optional[int] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        """
        Run an infinite async loop that sends heartbeats every `interval` seconds.
        Designed to be launched as an asyncio background task.

        Parameters
        ----------
        interval : int, optional
            Override the heartbeat interval (seconds). Defaults to self.heartbeat_interval.
        on_error : callable, optional
            Called with the exception if a heartbeat fails after all retries.

        Example
        -------
            asyncio.create_task(client.run_heartbeat_loop())
        """
        wait = interval or self.heartbeat_interval
        logger.info("[%s] Starting heartbeat loop (interval=%ds)", self.node_id, wait)
        while True:
            try:
                await asyncio.sleep(wait)
                await self.send_heartbeat()
            except asyncio.CancelledError:
                logger.info("[%s] Heartbeat loop cancelled", self.node_id)
                break
            except Exception as exc:
                logger.error("[%s] Heartbeat failed: %s", self.node_id, exc)
                if on_error:
                    on_error(exc)

    def start_heartbeat_task(self, interval: Optional[int] = None) -> asyncio.Task:
        """
        Convenience method: start the heartbeat loop as a background asyncio.Task.
        Must be called inside a running event loop.

        Returns the asyncio.Task so the caller can cancel it on shutdown.
        """
        task = asyncio.create_task(self.run_heartbeat_loop(interval=interval))
        self._heartbeat_task = task
        return task

    def stop_heartbeat_task(self) -> None:
        """Cancel the background heartbeat task if running."""
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "CoordinatorClient":
        await self.register()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop_heartbeat_task()
        try:
            await self.deregister()
        except Exception:
            pass
        finally:
            await self.close()

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"CoordinatorClient(node_id={self.node_id!r}, "
            f"protocol={self.protocol!r}, "
            f"coordinator={self.coordinator_url!r}, "
            f"registered={self._registered})"
        )

    @property
    def event_count(self) -> int:
        """Total events reported by this client since creation."""
        return self._event_count

    def set_status(self, status: str) -> None:
        """Update the node status (included in next heartbeat)."""
        self._status = status


# ---------------------------------------------------------------------------
# Synchronous wrapper (for honeypots not using asyncio)
# ---------------------------------------------------------------------------

class SyncCoordinatorClient:
    """
    Thin synchronous wrapper around CoordinatorClient.
    Useful for honeypots that are not async (e.g. the existing socket-based ones).

    Example
    -------
        client = SyncCoordinatorClient(node_id="ftp-node-1", host="0.0.0.0", port=21, protocol="FTP")
        client.register()
        client.report_event(src_ip="192.168.1.5")
        client.deregister()
    """

    def __init__(self, **kwargs: Any) -> None:
        self._async_client = CoordinatorClient(**kwargs)
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()

    def _run(self, coro: Any) -> Any:
        return self._loop.run_until_complete(coro)

    def register(self) -> Dict[str, Any]:
        return self._run(self._async_client.register())

    def send_heartbeat(self, **kwargs: Any) -> Dict[str, Any]:
        return self._run(self._async_client.send_heartbeat(**kwargs))

    def report_event(self, **kwargs: Any) -> Dict[str, Any]:
        return self._run(self._async_client.report_event(**kwargs))

    def report_alert(self, **kwargs: Any) -> Dict[str, Any]:
        return self._run(self._async_client.report_alert(**kwargs))

    def get_threats(self) -> Dict[str, Any]:
        return self._run(self._async_client.get_threats())

    def get_nodes(self, **kwargs: Any) -> Dict[str, Any]:
        return self._run(self._async_client.get_nodes(**kwargs))

    def deregister(self, reason: str = "graceful_shutdown") -> Dict[str, Any]:
        return self._run(self._async_client.deregister(reason=reason))

    def close(self) -> None:
        self._run(self._async_client.close())
        self._loop.close()

    @property
    def event_count(self) -> int:
        return self._async_client.event_count
