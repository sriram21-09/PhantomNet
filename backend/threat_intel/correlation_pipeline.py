class ThreatCorrelationEngine:
    """
    Correlates threat intel with detection signals
    """

    def correlate(self, indicators):
        results = []

        for item in indicators:
            score = 0.9 if item["type"] == "ip" else 0.4
            correlated = item.copy()
            correlated["correlation_score"] = score
            results.append(correlated)

        return results


if __name__ == "__main__":
    sample = [
        {"ioc": "1.1.1.1", "type": "ip", "threat": "malicious"}
    ]

    engine = ThreatCorrelationEngine()
    print(engine.correlate(sample))
