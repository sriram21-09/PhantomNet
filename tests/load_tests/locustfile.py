from locust import HttpUser, task, between
import random

class PhantomNetUser(HttpUser):
    """
    Simulates a PhantomNet SOC Analyst utilizing the dashboard.
    This generates a mix of traffic to various reporting endpoints.
    """
    # Wait between 0.1 and 1 seconds between tasks, 
    # ensuring high aggressive throughput when 500+ users are spawned.
    wait_time = between(0.1, 1.0)

    @task(3)
    def fetch_events(self):
        """
        High frequency polling: The dashboard constantly fetches recent events.
        """
        threat_levels = ["ALL", "MALICIOUS", "SUSPICIOUS", "BENIGN"]
        protocols = ["ALL", "SSH", "HTTP", "SMTP", "FTP"]
        
        threat = random.choice(threat_levels)
        protocol = random.choice(protocols)
        
        self.client.get(f"/api/events?threat={threat}&protocol={protocol}&limit=50", name="/api/events")

    @task(2)
    def fetch_stats(self):
        """
        Medium frequency polling: Aggregated dashboard statistics.
        This queries multiple tables and performs COUNT/GROUP BY operations.
        """
        self.client.get("/api/stats", name="/api/stats")

    @task(2)
    def fetch_live_traffic_feed(self):
        """
        Medium frequency polling: The real-time ML analysis feed.
        """
        self.client.get("/analyze-traffic", name="/analyze-traffic")

    @task(1)
    def fetch_honeypot_status(self):
        """
        Low frequency polling: Container/Socket health checks.
        This endpoint opens TCP sockets to honeypots, which is an I/O bound bottleneck.
        """
        self.client.get("/api/honeypots/status", name="/api/honeypots/status")

    @task(1)
    def fetch_advanced_patterns(self):
        """
        Low frequency polling: Complex time-series heuristic scanning.
        Heaviest DB load.
        """
        self.client.get("/api/v1/patterns/advanced", name="/api/v1/patterns/advanced")

    @task(1)
    def fetch_protocol_analytics_ssh(self):
        self.client.get("/api/v1/analytics/ssh", name="/api/v1/analytics/ssh")

    @task(1)
    def fetch_protocol_analytics_http(self):
        self.client.get("/api/v1/analytics/http", name="/api/v1/analytics/http")

    @task(1)
    def fetch_trends(self):
        days = random.randint(1, 30)
        self.client.get(f"/api/v1/analytics/trends?days={days}", name="/api/v1/analytics/trends")
