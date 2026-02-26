import requests

class GeoService:
    _cache = {}

    @staticmethod
    def get_geo_info(ip: str):
        # 1. Check phantomnet_postgres / Private IPs
        if ip in ["127.0.0.1", "phantomnet_postgres", "::1"]:
            return {"country": "Local", "city": "Internal", "lat": 0.0, "lon": 0.0, "flag": "🏳️"}
        
        if ip.startswith("192.168.") or ip.startswith("10."):
            return {"country": "LAN", "city": "Internal", "lat": 0.0, "lon": 0.0, "flag": "🏠"}

        # 2. Check Cache
        if ip in GeoService._cache:
            return GeoService._cache[ip]

        # 3. Ask the Internet (ip-api.com)
        try:
            fields = "status,message,country,countryCode,city,lat,lon"
            response = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    flag = GeoService.get_flag_emoji(data.get("countryCode"))
                    geo_data = {
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "flag": flag
                    }
                    GeoService._cache[ip] = geo_data
                    return geo_data
        except:
            pass

        return {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0, "flag": "🌐"}

        return "🌐"

    @staticmethod
    def get_flag_emoji(country_code):
        # Magic math to turn "US" into 🇺🇸
        if not country_code or len(country_code) != 2:
            return "🌐"
        
        OFFSET = 127397
        code = country_code.upper()
        return chr(ord(code[0]) + OFFSET) + chr(ord(code[1]) + OFFSET)
