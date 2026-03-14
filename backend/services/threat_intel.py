import os
import httpx
import logging
import asyncio
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pymisp import PyMISP, MISPEvent

# Setup Logger
logger = logging.getLogger("threat_intel")
logger.setLevel(logging.INFO)


class ThreatIntelService:
    """
    Professional Service for enriching IP traffic with external threat intelligence.
    Uses asynchronous I/O with httpx for high performance and non-blocking calls.
    Supports AbuseIPDB and AlienVault OTX.
    """

    def __init__(self):
        self.abuse_ipdb_key = os.getenv("ABUSE_IPDB_KEY")
        self.alien_vault_key = os.getenv("ALIENVAULT_OTX_KEY")
        self.misp_url = os.getenv("MISP_URL")
        self.misp_key = os.getenv("MISP_KEY")
        self._cache = {}  # In-memory cache: {ip: {"data": data, "timestamp": ts}}
        self._cache_ttl = 3600  # 1 hour
        self.client = httpx.AsyncClient(
            timeout=10.0,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        )

        # Initialize MISP client if configured
        self.misp = None
        if self.misp_url and self.misp_key:
            try:
                self.misp = PyMISP(self.misp_url, self.misp_key, ssl=False)
            except Exception as e:
                logger.error(f"Failed to connect to MISP: {e}")

    async def close(self):
        """Close the underlying HTTPX client."""
        await self.client.aclose()

    def _get_cached(self, ip: str) -> Optional[Dict[str, Any]]:
        if ip in self._cache:
            entry = self._cache[ip]
            if datetime.now() - entry["timestamp"] < timedelta(seconds=self._cache_ttl):
                return entry["data"]
            else:
                del self._cache[ip]
        return None

    def _set_cached(self, ip: str, data: Dict[str, Any]):
        self._cache[ip] = {"data": data, "timestamp": datetime.now()}

    async def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        Main entry point for enriching a single IP asynchronously.
        """
        # Exclude private/local IPs
        if ip in ["127.0.0.1", "phantomnet_postgres", "::1"] or ip.startswith(
            ("192.168.", "10.", "172.")
        ):
            return {
                "source": "local",
                "status": "trusted",
                "message": "Internal/Local IP",
            }

        cached_data = self._get_cached(ip)
        if cached_data:
            return cached_data

        # Fetch from both providers concurrently
        abuse_task = self._fetch_abuse_ipdb(ip)
        otx_task = self._fetch_alienvault_otx(ip)

        abuse_res, otx_res = await asyncio.gather(abuse_task, otx_task)

        enrichment = {
            "ip": ip,
            "abuse_ipdb": abuse_res,
            "alienvault_otx": otx_res,
            "timestamp": datetime.now().isoformat(),
        }

        self._set_cached(ip, enrichment)
        return enrichment

    async def _fetch_abuse_ipdb(self, ip: str) -> Dict[str, Any]:
        """Fetches data from AbuseIPDB API asynchronously."""
        if not self.abuse_ipdb_key:
            return {"status": "error", "message": "API Key missing"}

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": self.abuse_ipdb_key}

        try:
            response = await self.client.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "is_whitelist": data.get("isWhitelisted", False),
                }
            else:
                logger.warning(
                    f"AbuseIPDB request failed for {ip}: {response.status_code}"
                )
                return {"status": "error", "code": response.status_code}
        except Exception as e:
            logger.error(f"Error fetching from AbuseIPDB for {ip}: {e}")
            return {"status": "error", "message": "Connection error"}

    async def _fetch_alienvault_otx(self, ip: str) -> Dict[str, Any]:
        """Fetches data from AlienVault OTX API asynchronously."""
        if not self.alien_vault_key:
            return {"status": "error", "message": "API Key missing"}

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.alien_vault_key}

        try:
            response = await self.client.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                return {
                    "pulse_count": pulse_info.get("count", 0),
                    "reputation": data.get("reputation", 0),
                    "last_seen": data.get("last_seen"),
                    "tags": data.get("tags", []),
                }
            else:
                logger.warning(
                    f"AlienVault OTX request failed for {ip}: {response.status_code}"
                )
                return {"status": "error", "code": response.status_code}
        except Exception as e:
            logger.error(f"Error fetching from AlienVault OTX for {ip}: {e}")
            return {"status": "error", "message": "Connection error"}

    async def push_to_misp(self, ioc_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Pushes IOCs to connected MISP instance."""
        if not self.misp:
            return {"status": "ignored", "message": "MISP not configured"}

        try:
            event = MISPEvent()
            event.info = (
                f"PhantomNet Automated Feed - {datetime.now().strftime('%Y-%m-%d')}"
            )
            event.published = True

            for ioc in ioc_data:
                misp_type = (
                    "ip-dst"
                    if ioc["type"] == "ips"
                    else "domain" if ioc["type"] == "domains" else "url"
                )
                event.add_attribute(
                    misp_type, ioc["value"], comment=f"PhantomNet: {ioc['threat_type']}"
                )

            result = self.misp.add_event(event)
            return {"status": "success", "event_id": result.get("id")}
        except Exception as e:
            logger.error(f"MISP Push failed: {e}")
            return {"status": "error", "message": str(e)}

    async def push_to_otx(self, ioc_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submits indicators to AlienVault OTX via API."""
        if not self.alien_vault_key:
            return {"status": "ignored", "message": "AlienVault OTX key missing"}

        url = "https://otx.alienvault.com/api/v1/indicators/submit"
        headers = {
            "X-OTX-API-KEY": self.alien_vault_key,
            "Content-Type": "application/json",
        }

        # OTX submission payload
        payload = {
            "description": f"Automated PhantomNet threat indicators for {datetime.now().isoformat()}",
            "indicators": [
                {
                    "indicator": i["value"],
                    "type": "IPv4" if i["type"] == "ips" else "domain",
                }
                for i in ioc_data
            ],
        }

        try:
            response = await self.client.post(url, headers=headers, json=payload)
            if response.status_code in [200, 201]:
                return {"status": "success", "response": response.json()}
            return {"status": "error", "code": response.status_code}
        except Exception as e:
            logger.error(f"AlienVault OTX submission failed: {e}")
            return {"status": "error", "message": str(e)}

    def generate_daily_report(
        self,
        ioc_data: List[Dict[str, Any]],
        output_path: str = "reports/daily_threat_feed.json",
    ):
        """Generates a daily JSON report for public sharing."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "source": "PhantomNet AI",
                "version": "1.0",
            },
            "indicators": ioc_data,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)
        return output_path


# Singleton instance for general use
threat_intel_service = ThreatIntelService()
