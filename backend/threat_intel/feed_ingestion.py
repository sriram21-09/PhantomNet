class ThreatFeedIngestor:
    """
    Mock external threat feed ingestion
    """

    def load_feeds(self):
        return [
            {"ioc": "8.8.8.8", "type": "ip", "threat": "malicious"},
            {"ioc": "evil.com", "type": "domain", "threat": "phishing"},
        ]


if __name__ == "__main__":
    feeds = ThreatFeedIngestor().load_feeds()

    print("\n--- Loaded Threat Feeds ---")
    for feed in feeds:
        print(feed)
