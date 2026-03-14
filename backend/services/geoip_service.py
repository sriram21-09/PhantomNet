"""
PhantomNet GeoIP Service — MaxMind Integration
===============================================

Provides IP geolocation using MaxMind GeoLite2 database with
fallback to ip-api.com for when the local database is unavailable.

Setup:
    1. Create a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
    2. Download GeoLite2-City.mmdb
    3. Place it at: backend/data/GeoLite2-City.mmdb

Usage:
    from services.geoip_service import GeoIPService

    geo = GeoIPService()
    result = geo.lookup("8.8.8.8")
    # {'country': 'United States', 'city': 'Mountain View', 'lat': 37.386, 'lon': -122.0838, ...}
"""

import os
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Path to MaxMind database file
GEOIP_DB_PATH = os.getenv(
    "GEOIP_DB_PATH",
    os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "GeoLite2-City.mmdb"
    ),
)

# Private/reserved IP prefixes
PRIVATE_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "0.",
    "169.254.",
)

LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost", "phantomnet_postgres"}


class GeoIPService:
    """
    IP Geolocation service with MaxMind GeoLite2 and ip-api.com fallback.

    Priority:
        1. Private/loopback IP detection (instant, no lookup)
        2. In-memory cache (instant)
        3. MaxMind GeoLite2 local database (fast, offline)
        4. ip-api.com REST API (slow, online, rate-limited)
    """

    _instance = None
    _cache = {}
    _reader = None
    _maxmind_available = False

    def __new__(cls):
        """Singleton pattern — one reader, one cache."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Load MaxMind database if available."""
        try:
            import geoip2.database

            if os.path.exists(GEOIP_DB_PATH):
                self._reader = geoip2.database.Reader(GEOIP_DB_PATH)
                self._maxmind_available = True
                logger.info(f"[GeoIP] MaxMind database loaded: {GEOIP_DB_PATH}")
            else:
                logger.warning(
                    f"[GeoIP] MaxMind database not found at {GEOIP_DB_PATH}. "
                    f"Falling back to ip-api.com"
                )
        except ImportError:
            logger.warning(
                "[GeoIP] geoip2 package not installed. Using ip-api.com fallback"
            )
        except Exception as e:
            logger.error(f"[GeoIP] Failed to load MaxMind database: {e}")

    def lookup(self, ip: str) -> dict:
        """
        Look up geolocation for an IP address.

        Returns:
            dict with keys: country, country_code, city, lat, lon, flag, source
        """
        # 1. Check private/loopback IPs
        if self._is_private_ip(ip):
            return self._private_result(ip)

        # 2. Check cache
        if ip in self._cache:
            return self._cache[ip]

        # 3. Try MaxMind (offline, fast)
        if self._maxmind_available:
            result = self._lookup_maxmind(ip)
            if result:
                self._cache[ip] = result
                return result

        # 4. Fallback to ip-api.com (online, slow)
        result = self._lookup_ipapi(ip)
        self._cache[ip] = result
        return result

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private, loopback, or reserved."""
        if ip in LOOPBACK_IPS:
            return True
        return any(ip.startswith(prefix) for prefix in PRIVATE_PREFIXES)

    def _private_result(self, ip: str) -> dict:
        """Return geo data for private/internal IPs."""
        if ip in LOOPBACK_IPS:
            label = "Loopback"
        elif ip.startswith("10."):
            label = "LAN (10.x)"
        elif ip.startswith("192.168."):
            label = "LAN (192.168.x)"
        else:
            label = "Internal"

        return {
            "country": "Local Network",
            "country_code": "LAN",
            "city": label,
            "lat": 0.0,
            "lon": 0.0,
            "flag": "🏠",
            "source": "private",
        }

    def _lookup_maxmind(self, ip: str) -> Optional[dict]:
        """Look up IP in MaxMind GeoLite2 database."""
        try:
            response = self._reader.city(ip)
            country = response.country.name or "Unknown"
            country_code = response.country.iso_code or "XX"
            city = response.city.name or "Unknown"
            lat = response.location.latitude or 0.0
            lon = response.location.longitude or 0.0

            return {
                "country": country,
                "country_code": country_code,
                "city": city,
                "lat": lat,
                "lon": lon,
                "flag": self._get_flag_emoji(country_code),
                "source": "maxmind",
            }
        except Exception as e:
            logger.debug(f"[GeoIP] MaxMind lookup failed for {ip}: {e}")
            return None

    def _lookup_ipapi(self, ip: str) -> dict:
        """Fallback: look up IP using ip-api.com REST API."""
        try:
            import requests

            fields = "status,message,country,countryCode,city,lat,lon"
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields={fields}", timeout=3
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    country_code = data.get("countryCode", "XX")
                    return {
                        "country": data.get("country", "Unknown"),
                        "country_code": country_code,
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "flag": self._get_flag_emoji(country_code),
                        "source": "ip-api",
                    }
        except Exception as e:
            logger.debug(f"[GeoIP] ip-api.com lookup failed for {ip}: {e}")

        return {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "flag": "🌐",
            "source": "none",
        }

    @staticmethod
    def _get_flag_emoji(country_code: str) -> str:
        """Convert ISO country code to flag emoji (e.g., 'US' → 🇺🇸)."""
        if not country_code or len(country_code) != 2:
            return "🌐"
        OFFSET = 127397
        code = country_code.upper()
        return chr(ord(code[0]) + OFFSET) + chr(ord(code[1]) + OFFSET)

    def enrich_record(self, ip: str) -> dict:
        """
        Return geo data formatted for database column enrichment.

        Returns dict with keys matching DB columns:
            country, city, latitude, longitude
        """
        geo = self.lookup(ip)
        return {
            "country": geo["country"],
            "city": geo["city"],
            "latitude": geo["lat"],
            "longitude": geo["lon"],
        }

    def batch_enrich(self, ip_list: list) -> dict:
        """
        Enrich a list of IPs at once. Returns {ip: geo_data} mapping.
        Useful for backfilling existing database records.
        """
        results = {}
        for ip in set(ip_list):  # Deduplicate
            results[ip] = self.enrich_record(ip)
        return results

    @property
    def stats(self) -> dict:
        """Return service statistics."""
        return {
            "maxmind_available": self._maxmind_available,
            "db_path": GEOIP_DB_PATH if self._maxmind_available else None,
            "cache_size": len(self._cache),
            "fallback": "ip-api.com",
        }

    def close(self):
        """Close the MaxMind reader."""
        if self._reader:
            self._reader.close()
            logger.info("[GeoIP] MaxMind reader closed")


# ──────────────────────────────────────────────
# Module-level singleton for easy import
# ──────────────────────────────────────────────
geoip_service = GeoIPService()
