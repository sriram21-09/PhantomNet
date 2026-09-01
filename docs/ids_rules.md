# IDS Rule Generation and Detection Formats Documentation

## 1. Overview
This document outlines the mechanisms for automated Snort and Sigma rule generation, syntax validation, deduplication, and the export processes within the Sentinel Layer.

## 2. Snort Rule Generation
The system supports automated generation of both Snort 2.9 and Snort 3.0 rules for Network Intrusion Detection.

### 2.1 Rule Structure
A standard Snort rule consists of a rule header and rule options.
*   **Rule Header**: Defines the action, protocol, source and destination IP addresses and netmasks, and the source and destination ports information.
    *   *Syntax*: `action protocol src_ip src_port direction dst_ip dst_port`
    *   *Example*: `alert tcp $EXTERNAL_NET any -> $HOME_NET 80`
*   **Rule Options**: Contains alert messages and information on which parts of the packet should be inspected to determine if the rule action should be taken.

### 2.2 Header Options & Keywords
*   `msg`: The message to be logged or alerted when the rule is triggered.
*   `classtype`: Categorizes the rule into a specific type of attack (e.g., `attempted-admin`, `trojan-activity`).
*   `sid` (Snort ID): A unique identifier for the rule. SIDs < 1,000,000 are reserved; local rules should start from 1,000,000.
*   `rev` (Revision): Indicates the revision number of the rule.
*   `reference`: Allows rules to include references to external vulnerability databases (e.g., CVE).

### 2.3 Thresholds
Thresholding is used to reduce the number of logged alerts for noisy rules.
*   `type`: Can be `limit` (alerts on the first m events), `threshold` (alerts every m times within t seconds), or `both`.
*   `track`: Can track by `by_src` or `by_dst`.
*   `count`: The number of events.
*   `seconds`: The time period.

## 3. Sigma Rule Generation
Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner.

### 3.1 YAML Schema Compliance
All generated Sigma rules must strictly adhere to the Sigma YAML schema. Key fields include:
*   `title`: A brief title for the rule.
*   `id`: A unique UUID.
*   `status`: Status of the rule (`experimental`, `test`, `stable`).
*   `description`: Detailed explanation of the rule.
*   `author`: Creator of the rule.
*   `date`: Creation date.

### 3.2 Logsource Mappings
The `logsource` section defines where to look for the logs.
*   `category`: e.g., `process_creation`, `file_event`.
*   `product`: e.g., `windows`, `linux`.
*   `service`: e.g., `sysmon`, `security`.

### 3.3 Condition Syntax
The `detection` section contains the search identifiers and the `condition` that evaluates them.
*   Search identifiers define specific fields and values to match (e.g., `Image|endswith: '\cmd.exe'`).
*   Conditions use logical operators (`1 of them`, `all of them`, `a and b`, `a or not b`) to combine search identifiers.

## 4. Rule Deduplication
To prevent performance degradation and alert fatigue, the system implements a deduplication algorithm before saving or exporting rules.

### 4.1 Deduplication Algorithm
1.  **Normalization**: All rules are parsed and normalized (whitespace removal, consistent casing for keywords).
2.  **Hashing**: A cryptographic hash (e.g., SHA-256) is generated based on the core logical components of the rule, ignoring metadata like `rev` or `date`.
    *   *Snort*: Hash based on Header + specific options (`content`, `pcre`).
    *   *Sigma*: Hash based on `logsource` + `detection` logic.
3.  **Comparison**: If a newly generated rule's hash matches an existing active rule in the database, it is flagged as a duplicate.
4.  **Action**: Duplicates are discarded, and a log entry is created. If the new rule contains updated metadata (e.g., new references), the existing rule is updated and its `rev` is incremented.

## 5. Export Mechanisms
The Sentinel Layer provides API endpoints for exporting generated rules.

### 5.1 Combined ZIP Export
*   **Endpoint**: `GET /api/v1/sentinel/rules/export-all`
*   **Description**: This endpoint packages all active Snort and Sigma rules into a single, structured ZIP archive.
*   **Structure**:
    ```text
    rules_export.zip
    ├── snort/
    │   ├── snort2/
    │   │   └── rules.rules
    │   └── snort3/
    │       └── rules.rules
    └── sigma/
        ├── windows/
        │   └── rules.yml
        └── linux/
            └── rules.yml
    ```
*   **Process**:
    1. Retrieves all active rules from the database.
    2. Groups them by type (Snort vs. Sigma) and category/platform.
    3. Generates the respective configuration/YAML files.
    4. Compresses the files into a ZIP archive and streams it to the client.
