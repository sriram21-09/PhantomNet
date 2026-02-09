import urllib.request
import json
import time

def test_status_endpoint():
    url = "http://127.0.0.1:8000/api/honeypots/status"
    print(f"Testing {url}...")
    try:
        with urllib.request.urlopen(url) as response:
            if response.getcode() == 200:
                raw_data = response.read().decode()
                print(f"RAW RESPONSE: {raw_data}")
                data = json.loads(raw_data)
                print("Successfully connected!")
                print("-" * 60)
                print(f"{'Service':<10} | {'Port':<6} | {'Status':<10} | {'Last Seen'}")
                print("-" * 60)
                for service in data:
                    print(f"{service.get('name', 'N/A'):<10} | {service.get('port', 0):<6} | {service.get('status', 'N/A'):<10} | {service.get('last_seen', 'N/A')}")
                print("-" * 60)
                return True
            else:
                print(f"Failed. Status Code: {response.getcode()}")
                return False
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
        print(f"Error Body: {e.read().decode()}")
        return False
    except urllib.error.URLError as e:
        print(f"Connection Failed: {e}")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Wait a bit for server to start if running via script
    time.sleep(2)
    test_status_endpoint()
