def main():
    # Local imports (safe when run directly)
    from feed_ingestion import ThreatFeedIngestor
    from correlation_pipeline import ThreatCorrelationEngine

    feed = ThreatFeedIngestor()
    engine = ThreatCorrelationEngine()

    indicators = feed.load_feeds()
    results = engine.correlate(indicators)

    print("\n--- Threat Correlation Results ---")
    for r in results:
        print(r)


if __name__ == "__main__":
    main()
