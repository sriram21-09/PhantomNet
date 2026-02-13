import requests

class GeoService:
    _cache = {}

    @staticmethod
    def get_country(ip: str):
        # 1. Check phantomnet_postgres / Private IPs
        if ip in ["127.0.0.1", "phantomnet_postgres", "::1"]:
            return "🏳️ Local"
        
        if ip.startswith("192.168.") or ip.startswith("10."):
            return "🏠 LAN"

        # 2. Check Cache (Don't limit yourself by spamming the API)
        if ip in GeoService._cache:
            return GeoService._cache[ip]

        # 3. Ask the Internet (ip-api.com)
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=2)
            if response.status_code == 200:
                data = response.json()
                country = data.get("countryCode", "??")
                
                # Convert "US" -> 🇺🇸
                flag = GeoService.get_flag_emoji(country)
                GeoService._cache[ip] = flag
                return flag
        except:
            return "🌐" # Return Globe if internet fails

        return "🌐"

    @staticmethod
    def get_flag_emoji(country_code):
        # Magic math to turn "US" into 🇺🇸
        if not country_code or len(country_code) != 2:
            return "🌐"
        
        OFFSET = 127397
        code = country_code.upper()
        return chr(ord(code[0]) + OFFSET) + chr(ord(code[1]) + OFFSET)
