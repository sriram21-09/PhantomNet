import React from "react";
import PropTypes from "prop-types";
import "../../Styles/components/MitreMatrix.css";

/**
 * Standard MITRE ATT&CK Tactics (12 Tactics Enterprise Subset)
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
 * MitreMatrix - Component representing the MITRE ATT&CK Matrix layout scaffold.
 * Displays 12 standard tactics as column headers and empty technique cell placeholders.
 */
const MitreMatrix = ({
  placeholderCount = 6,
  onCellClick = null,
}) => {
  // Generate array for rendering a fixed number of empty placeholders under each tactic
  const placeholderIds = Array.from({ length: placeholderCount }, (_, idx) => idx);

  const handleCellClick = (tacticId, cellIndex) => {
    if (onCellClick) {
      onCellClick(tacticId, cellIndex);
    }
  };

  return (
    <div className="mitre-matrix-container">
      <div className="mitre-matrix-grid">
        {TACTICS.map((tactic) => (
          <div key={tactic.id} className="tactic-column">
            {/* Tactic Column Header */}
            <div className={`tactic-header tactic-${tactic.id}`}>
              <span className="tactic-title">{tactic.label}</span>
              <span className="tactic-count-badge">0 Techs</span>
            </div>

            {/* Technique Cell Placeholders */}
            {placeholderIds.map((cellIndex) => {
              // Apply alternating pulsing effect to make placeholders feel alive and dynamic
              const shouldPulse = (cellIndex % 3 === 0);
              return (
                <div
                  key={cellIndex}
                  className={`technique-placeholder ${shouldPulse ? "technique-placeholder-pulse" : ""}`}
                  onClick={() => handleCellClick(tactic.id, cellIndex)}
                  title={`Placeholder for tactic: ${tactic.label}`}
                >
                  <span className="placeholder-content">
                    {`T${1000 + cellIndex * 77}`}
                  </span>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
};

MitreMatrix.propTypes = {
  placeholderCount: PropTypes.number,
  onCellClick: PropTypes.func,
};

export default MitreMatrix;
