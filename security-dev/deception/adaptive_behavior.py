import time
import random


class AdaptiveEngine:
    def __init__(self, profile="Vulnerable"):
        self.profile = profile
        self.profiles = {
            "Vulnerable": {
                "min_delay": 0.05,
                "max_delay": 0.2,
                "banner_randomization": True,
                "response_type": "standard_error",
            },
            "Hardened": {
                "min_delay": 0.5,
                "max_delay": 2.0,
                "banner_randomization": False,
                "response_type": "obfuscated",
            },
            "Interactive": {
                "min_delay": 0.2,
                "max_delay": 0.5,
                "banner_randomization": True,
                "response_type": "detailed_feedback",
            },
        }

    def set_profile(self, profile):
        if profile in self.profiles:
            self.profile = profile
            print(f"Behavior profile switched to: {profile}")

    def apply_delay(self):
        config = self.profiles.get(self.profile)
        delay = random.uniform(config["min_delay"], config["max_delay"])
        time.sleep(delay)
        return delay

    def tarpit(self, attempt_count, base_delay=1.0):
        # Exponential backoff for repeated attempts (brute force mitigation)
        if attempt_count > 3:
            delay = base_delay * (2 ** (attempt_count - 3))
            print(f"Tarpit active: delaying response by {delay} seconds.")
            time.sleep(delay)
            return delay
        return 0

    def get_spoofed_banner(self, service_type):
        if service_type == "SSH":
            banners = [
                "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                "OpenSSH_7.4",
                "OpenSSH_8.9p1 Ubuntu-3ubuntu1",
            ]
        elif service_type == "HTTP":
            banners = [
                "Apache/2.4.41 (Ubuntu)",
                "nginx/1.18.0 (Ubuntu)",
                "Microsoft-IIS/10.0",
            ]
        elif service_type == "SMTP":
            banners = ["Postfix (Ubuntu)", "Exim 4.93", "Sendmail 8.15.2"]
        else:
            banners = ["Generic Service 1.0"]

        if self.profiles[self.profile]["banner_randomization"]:
            return random.choice(banners)
        return banners[0]


if __name__ == "__main__":
    engine = AdaptiveEngine(profile="Hardened")
    print(f"Applying delay for Hardened profile...")
    engine.apply_delay()
    print(f"Tarpitting 5th attempt...")
    engine.tarpit(5)
    print(f"Spoofed Banner: {engine.get_spoofed_banner('SSH')}")
