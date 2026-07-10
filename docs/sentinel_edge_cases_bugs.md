# Sentinel Edge Cases and Bug Documentation

This document outlines the edge cases tested and bugs identified during the Week 16 Day 2 Sentinel edge case testing.

## Identified Bugs

### 1. Missing Deduplication in `rule_generator.py` (Performance Bug)
* **Description**: When a large campaign cluster was passed to `generate_rules_for_campaign` (e.g. 1000 identical ports in the `target_ports` list and 255 unique IPs), it resulted in a Cartesian product of non-deduplicated fields. This caused `generate_snort_rule` to be called excessively (e.g., 255,000 times), causing significant performance degradation and hanging the pipeline execution.
* **Fix**: Added deduplication logic to `validated_sources`, `validated_ports`, and `snort_supported_protocols` directly in `rule_generator.py`. This ensures we only generate combinations for mathematically unique IPs, ports, and protocols.

### 2. Missing Duplicate Campaign Detection in `sentinel_service.py` (Logic Bug)
* **Description**: The `generate_playbook` function in `SentinelService` lacked any mechanism to detect if a playbook for a specific `campaign_id` had already been generated. Submitting the same cluster payload twice resulted in two redundant playbooks being generated and persisted in the database.
* **Fix**: Implemented a simple in-memory deduplication cache `_seen_campaigns` in `SentinelService`. The service now checks this cache at the start of `generate_playbook` and immediately returns the existing playbook if the `campaign_id` was already processed.

### 3. Missing `id` attribute logic for mocked Playbooks (Testing/Logging Bug)
* **Description**: The `SentinelService.generate_playbook` logger used `%d` format to log `playbook_record.id` at step 8. When testing with mocked SQLAlchemy database sessions, the returned `.id` was `NoneType`, which crashed the generation process with `TypeError: %d format: a real number is required, not NoneType`.
* **Fix**: Changed the logger format string from `%d` to `%s` to gracefully format the `id` even if the underlying database driver (or mock) hasn't populated an auto-incremented integer.

## Test Coverage
The edge cases covered in `tests/test_sentinel_edge_cases.py` are:
1. `test_empty_cluster_input`: Empty dictionaries are handled without crashing (defaults to single placeholder payload).
2. `test_single_event_campaign`: Minimum valid payloads still successfully generate valid playbooks.
3. `test_unknown_protocol`: Fallback mapping to `T1046 (Discovery)` is applied if an unknown service port is detected.
4. `test_malformed_ip_addresses_rule_generator`: IPv6 and malformed strings are correctly flagged and rejected by `validate_ip` before rules are compiled.
5. `test_large_cluster`: Ensures performance scaling on 1000+ payload clusters. Timeouts prevent hangs.
6. `test_duplicate_campaign_detection`: Ensures a single campaign cluster isn't generated twice, avoiding database redundancy.
