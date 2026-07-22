import React from "react";
import PropTypes from "prop-types";
import "../../Styles/components/MitreMatrix.css";

/**
 * Standard MITRE ATT&CK Tactics (12 Enterprise Subset)
 */
const TACTICS = [
  { id: "initial-access",         label: "Initial Access" },
  { id: "execution",              label: "Execution" },
  { id: "persistence",            label: "Persistence" },
  { id: "privilege-escalation",    label: "Privilege Escalation" },
  { id: "defense-evasion",        label: "Defense Evasion" },
  { id: "credential-access",      label: "Credential Access" },
  { id: "discovery",              label: "Discovery" },
  { id: "lateral-movement",       label: "Lateral Movement" },
  { id: "collection",             label: "Collection" },
  { id: "command-and-control",    label: "Command and Control" },
  { id: "exfiltration",           label: "Exfiltration" },
  { id: "impact",                 label: "Impact" },
];

/**
 * Standard MITRE ATT&CK Techniques mapping per Tactic
 */
const TACTIC_TECHNIQUES = {
  "initial-access": [
    { id: "T1190", name: "Exploit Public-Facing Application" },
    { id: "T1566", name: "Phishing" },
    { id: "T1078", name: "Valid Accounts" },
    { id: "T1133", name: "External Remote Services" },
    { id: "T1189", name: "Drive-by Compromise" },
    { id: "T1195", name: "Supply Chain Compromise" },
  ],
  "execution": [
    { id: "T1059", name: "Command & Scripting Interpreter" },
    { id: "T1204", name: "User Execution" },
    { id: "T1053", name: "Scheduled Task/Job" },
    { id: "T1569", name: "System Services" },
    { id: "T1106", name: "Native API" },
    { id: "T1047", name: "Windows Management Instrumentation" },
  ],
  "persistence": [
    { id: "T1547", name: "Boot or Logon Autostart" },
    { id: "T1053", name: "Scheduled Task/Job" },
    { id: "T1136", name: "Create Account" },
    { id: "T1543", name: "Create or Modify System Process" },
    { id: "T1546", name: "Event Triggered Execution" },
    { id: "T1098", name: "Account Manipulation" },
  ],
  "privilege-escalation": [
    { id: "T1068", name: "Exploitation for Privilege Escalation" },
    { id: "T1548", name: "Abuse Elevation Control" },
    { id: "T1055", name: "Process Injection" },
    { id: "T1574", name: "Hijack Execution Flow" },
    { id: "T1053", name: "Scheduled Task/Job" },
    { id: "T1547", name: "Boot or Logon Autostart" },
  ],
  "defense-evasion": [
    { id: "T1027", name: "Obfuscated Files or Info" },
    { id: "T1070", name: "Indicator Removal" },
    { id: "T1036", name: "Masquerading" },
    { id: "T1218", name: "System Binary Proxy Execution" },
    { id: "T1112", name: "Modify Registry" },
    { id: "T1562", name: "Impair Defenses" },
  ],
  "credential-access": [
    { id: "T1003", name: "OS Credential Dumping" },
    { id: "T1110", name: "Brute Force" },
    { id: "T1555", name: "Credentials from Password Stores" },
    { id: "T1552", name: "Unsecured Credentials" },
    { id: "T1056", name: "Input Capture" },
    { id: "T1558", name: "Steal or Forge Kerberos Tickets" },
  ],
  "discovery": [
    { id: "T1082", name: "System Information Discovery" },
    { id: "T1083", name: "File and Directory Discovery" },
    { id: "T1018", name: "Remote System Discovery" },
    { id: "T1046", name: "Network Service Discovery" },
    { id: "T1057", name: "Process Discovery" },
    { id: "T1087", name: "Account Discovery" },
  ],
  "lateral-movement": [
    { id: "T1021", name: "Remote Services" },
    { id: "T1570", name: "Lateral Tool Transfer" },
    { id: "T1091", name: "Replication Through Removable Media" },
    { id: "T1550", name: "Use Alternate Auth Material" },
    { id: "T1563", name: "Remote Service Session Hijacking" },
    { id: "T1210", name: "Exploitation of Remote Services" },
  ],
  "collection": [
    { id: "T1114", name: "Email Collection" },
    { id: "T1056", name: "Input Capture" },
    { id: "T1005", name: "Data from Local System" },
    { id: "T1115", name: "Clipboard Data" },
    { id: "T1125", name: "Video Capture" },
    { id: "T1560", name: "Archive Collected Data" },
  ],
  "command-and-control": [
    { id: "T1071", name: "Application Layer Protocol" },
    { id: "T1095", name: "Non-Application Layer Protocol" },
    { id: "T1573", name: "Encrypted Channel" },
    { id: "T1105", name: "Ingress Tool Transfer" },
    { id: "T1090", name: "Proxy" },
    { id: "T1219", name: "Remote Access Software" },
  ],
  "exfiltration": [
    { id: "T1041", name: "Exfiltration Over C2 Channel" },
    { id: "T1020", name: "Automated Exfiltration" },
    { id: "T1048", name: "Exfiltration Over Alt Protocol" },
    { id: "T1567", name: "Exfiltration to Cloud Storage" },
    { id: "T1052", name: "Exfiltration Over Physical Medium" },
    { id: "T1030", name: "Data Transfer Size Limits" },
  ],
  "impact": [
    { id: "T1485", name: "Data Destruction" },
    { id: "T1486", name: "Data Encrypted for Impact" },
    { id: "T1489", name: "Service Stop" },
    { id: "T1529", name: "System Shutdown/Reboot" },
    { id: "T1490", name: "Inhibit System Recovery" },
    { id: "T1498", name: "Network Denial of Service" },
  ],
};

/**
 * Calculates heat intensity level based on frequency count.
 * @param {number} count
 * @returns {'none'|'low'|'medium'|'high'}
 */
const getHeatLevel = (count) => {
  if (!count || count <= 0) return "none";
  if (count <= 3) return "low";
  if (count <= 8) return "medium";
  return "high";
};

/**
 * MitreMatrix - MITRE ATT&CK Matrix Heatmap component.
 * Displays 12 standard tactics as column headers and renders technique cells styled
 * with dynamic heat colors corresponding to detection frequency counts.
 */
const MitreMatrix = ({
  techniqueFrequencies = null,
  techniquesData = null,
  data = null,
  placeholderCount = 6,
  onCellClick = null,
  onTechniqueClick = null,
}) => {
  // Normalize incoming frequency data into a fast lookup map: { [techniqueId]: count }
  const rawData = techniqueFrequencies || techniquesData || data;

  const frequencyMap = React.useMemo(() => {
    if (!rawData) return {};

    // Case 1: Array of technique objects (e.g., [{ id: "T1059", count: 12 }, ...])
    if (Array.isArray(rawData)) {
      return rawData.reduce((acc, item) => {
        const id = item.id || item.technique_id || item.techniqueId;
        const count = item.count ?? item.frequency ?? item.hits ?? 0;
        if (id) acc[id] = count;
        return acc;
      }, {});
    }

    // Case 2: Object mapping IDs to numbers or nested objects (e.g., { T1059: 12 } or { T1059: { count: 12 } })
    if (typeof rawData === "object") {
      const acc = {};
      Object.entries(rawData).forEach(([key, val]) => {
        if (typeof val === "number") {
          acc[key] = val;
        } else if (Array.isArray(val)) {
          // Case 3: Tactic-grouped nested arrays of technique objects (e.g. { Tactic: [ { technique_id: 'T1059', count: 12 } ] })
          val.forEach((tech) => {
            const id = tech.technique_id || tech.id || tech.techniqueId;
            const count = tech.count ?? tech.frequency ?? tech.hits ?? 0;
            if (id) {
              acc[id] = count;
              // Sum counts of sub-techniques to parent technique IDs
              if (typeof id === "string" && id.includes(".")) {
                const baseId = id.split(".")[0];
                acc[baseId] = (acc[baseId] || 0) + count;
              }
            }
          });
        } else if (val && typeof val === "object") {
          acc[key] = val.count ?? val.frequency ?? val.hits ?? 0;
        }
      });
      return acc;
    }

    return {};
  }, [rawData]);

  const handleCellClick = (tacticId, technique, count, heatLevel) => {
    const detailPayload = { tacticId, ...technique, count, heatLevel };
    if (onTechniqueClick) {
      onTechniqueClick(detailPayload);
    }
    if (onCellClick) {
      onCellClick(tacticId, detailPayload);
    }
  };

  return (
    <div className="mitre-matrix-container">
      <div className="mitre-matrix-grid">
        {TACTICS.map((tactic) => {
          const defaultTechniques = TACTIC_TECHNIQUES[tactic.id] || [];
          
          // Limit or expand techniques based on placeholderCount if default list is sliced
          const displayTechniques = defaultTechniques.slice(0, Math.max(placeholderCount, defaultTechniques.length));

          // Calculate tactic column metrics
          let activeTechCount = 0;
          let totalFrequencyHits = 0;

          displayTechniques.forEach((tech) => {
            const count = frequencyMap[tech.id] || 0;
            if (count > 0) {
              activeTechCount += 1;
              totalFrequencyHits += count;
            }
          });

          return (
            <div key={tactic.id} className="tactic-column">
              {/* Tactic Header */}
              <div className={`tactic-header tactic-${tactic.id}`}>
                <span className="tactic-title">{tactic.label}</span>
                <span className="tactic-count-badge">
                  {activeTechCount > 0 ? `${activeTechCount} Techs (${totalFrequencyHits})` : "0 Techs"}
                </span>
              </div>

              {/* Technique Heatmap Cells */}
              {displayTechniques.map((technique) => {
                const count = frequencyMap[technique.id] || 0;
                const heatLevel = getHeatLevel(count);

                return (
                  <div
                    key={technique.id}
                    className={`technique-cell heat-${heatLevel}`}
                    onClick={() => handleCellClick(tactic.id, technique, count, heatLevel)}
                    title={`${technique.id} - ${technique.name} (${count} detection${count === 1 ? "" : "s"})`}
                  >
                    <div className="technique-cell-top">
                      <span className="technique-id">{technique.id}</span>
                      <span className="heat-count-chip">{count}</span>
                    </div>
                    <span className="technique-name">{technique.name}</span>
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );
};

MitreMatrix.propTypes = {
  techniqueFrequencies: PropTypes.oneOfType([PropTypes.object, PropTypes.array]),
  techniquesData: PropTypes.oneOfType([PropTypes.object, PropTypes.array]),
  data: PropTypes.oneOfType([PropTypes.object, PropTypes.array]),
  placeholderCount: PropTypes.number,
  onCellClick: PropTypes.func,
  onTechniqueClick: PropTypes.func,
};

export default MitreMatrix;
