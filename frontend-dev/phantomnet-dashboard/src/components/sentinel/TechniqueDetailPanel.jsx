import React, { useState, useEffect } from "react";
import PropTypes from "prop-types";
import { FaTimes, FaExternalLinkAlt, FaShieldAlt, FaRegFolderOpen, FaInfoCircle, FaCalendarAlt } from "react-icons/fa";
import "../../Styles/components/TechniqueDetailPanel.css";

/**
 * TechniqueDetailPanel - Slide-out drawer displaying details of a selected MITRE technique.
 * Shows description, severity, tactic mapping, and dynamically loaded associated playbooks.
 */
const TechniqueDetailPanel = ({
  isOpen = false,
  onClose,
  technique = null,
  onPlaybookClick = null,
}) => {
  const [associatedPlaybooks, setAssociatedPlaybooks] = useState([]);
  const [loadingPlaybooks, setLoadingPlaybooks] = useState(false);

  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  // Fetch playbooks associated with this technique dynamically
  useEffect(() => {
    if (!isOpen || !technique || !technique.id) {
      setAssociatedPlaybooks([]);
      return;
    }

    const fetchPlaybooks = async () => {
      setLoadingPlaybooks(true);
      try {
        const res = await fetch(`/api/sentinel/playbooks?technique_id=${technique.id}&per_page=50`);
        if (res.ok) {
          const data = await res.json();
          setAssociatedPlaybooks(data.playbooks || []);
        } else {
          console.warn("Failed to fetch associated playbooks: server returned non-ok status");
          setAssociatedPlaybooks([]);
        }
      } catch (err) {
        console.error("Failed to fetch associated playbooks for MITRE technique:", err);
        setAssociatedPlaybooks([]);
      } finally {
        setLoadingPlaybooks(false);
      }
    };

    fetchPlaybooks();
  }, [isOpen, technique]);

  if (!isOpen || !technique) return null;

  const {
    id: techniqueId,
    name: techniqueName,
    description = "No description available for this technique.",
    url = `https://attack.mitre.org/techniques/${technique.id.replace(/\./g, "/")}/`,
    severity = "MEDIUM",
    count = 0,
    tactic = "",
  } = technique;

  // Normalization logic for playbook status
  const getNormalizedStatus = (status) => {
    const s = status ? status.toLowerCase() : "";
    if (s === "pending") return "draft";
    if (s === "exported") return "approved";
    return s;
  };

  return (
    <>
      {/* Backdrop overlay */}
      <div className="technique-detail-backdrop" onClick={onClose} />

      {/* Slide-out Panel container */}
      <div className="technique-detail-panel" role="dialog" aria-modal="true" aria-labelledby="tech-panel-title">
        {/* Header */}
        <div className="technique-detail-header">
          <div className="technique-header-left">
            <div className="technique-meta-badges">
              <span className="tech-detail-id">{techniqueId}</span>
              {tactic && (
                <span className="tech-detail-tactic-badge">
                  {tactic.replace(/-/g, " ")}
                </span>
              )}
              <span className={`tech-detail-severity-badge ${severity.toLowerCase()}`}>
                {severity}
              </span>
            </div>
            <h2 id="tech-panel-title" className="technique-detail-title">
              {techniqueName}
            </h2>
          </div>
          <button
            className="technique-detail-close-btn"
            onClick={onClose}
            aria-label="Close details panel"
            title="Close Panel"
          >
            <FaTimes />
          </button>
        </div>

        {/* Content Body */}
        <div className="technique-detail-body">
          {/* Coverage Metrics */}
          <div className="tech-detail-section">
            <h3 className="tech-detail-section-title">
              <FaInfoCircle /> Metrics
            </h3>
            <div className="tech-metrics-grid">
              <div className="tech-metric-card">
                <span className="tech-metric-label">Detections count</span>
                <span className="tech-metric-value">{count}</span>
              </div>
              <div className="tech-metric-card">
                <span className="tech-metric-label">Playbooks loaded</span>
                <span className="tech-metric-value">{associatedPlaybooks.length}</span>
              </div>
            </div>
          </div>

          {/* Description */}
          <div className="tech-detail-section">
            <h3 className="tech-detail-section-title">Description</h3>
            <p className="tech-detail-desc">{description}</p>
          </div>

          {/* Associated Playbooks */}
          <div className="tech-detail-section" style={{ flex: 1, display: "flex", flexDirection: "column" }}>
            <h3 className="tech-detail-section-title">
              <FaShieldAlt /> Associated Playbooks
            </h3>
            <div className="tech-playbooks-list" style={{ flex: 1, overflowY: "auto", marginTop: "0.25rem" }}>
              {loadingPlaybooks ? (
                // Loading skeletons
                Array.from({ length: 3 }).map((_, idx) => (
                  <div key={idx} className="tech-playbook-skeleton" />
                ))
              ) : associatedPlaybooks.length === 0 ? (
                // Empty state
                <div className="tech-playbooks-empty">
                  <FaRegFolderOpen className="tech-playbooks-empty-icon" />
                  <h4 className="tech-playbooks-empty-title">No associated playbooks</h4>
                  <p className="tech-playbooks-empty-desc">
                    No playbooks found in the database mapped to this MITRE technique.
                  </p>
                </div>
              ) : (
                // Playbooks list
                associatedPlaybooks.map((pb) => {
                  const pbSeverity = pb.threat_score >= 90 ? "critical" : pb.threat_score >= 70 ? "high" : pb.threat_score >= 40 ? "medium" : "low";
                  const pbStatus = getNormalizedStatus(pb.status);

                  return (
                    <div
                      key={pb.id}
                      className="tech-playbook-item"
                      onClick={() => onPlaybookClick && onPlaybookClick(pb)}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onPlaybookClick && onPlaybookClick(pb);
                        }
                      }}
                      title="Click to view full response playbook details"
                    >
                      <div className="tech-playbook-top">
                        <span className="tech-playbook-title">
                          {pb.playbook_name || "Untitled Response Playbook"}
                        </span>
                        <div className="tech-playbook-badges">
                          <span className={`pb-badge severity-${pbSeverity}`}>
                            {pbSeverity}
                          </span>
                          <span className={`pb-badge status-${pbStatus}`}>
                            {pbStatus}
                          </span>
                        </div>
                      </div>
                      <div className="tech-playbook-meta">
                        <span>ID: {pb.playbook_id}</span>
                        <span style={{ display: "flex", alignItems: "center", gap: "0.25rem" }}>
                          <FaCalendarAlt />
                          {pb.created_at ? pb.created_at.substring(0, 10) : "—"}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* External Link */}
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="tech-detail-link-btn"
            title="Open official MITRE ATT&CK definition"
          >
            <FaExternalLinkAlt /> MITRE ATT&amp;CK Spec
          </a>
        </div>
      </div>
    </>
  );
};

TechniqueDetailPanel.propTypes = {
  isOpen: PropTypes.bool,
  onClose: PropTypes.func.isRequired,
  technique: PropTypes.shape({
    id: PropTypes.string.isRequired,
    name: PropTypes.string.isRequired,
    description: PropTypes.string,
    url: PropTypes.string,
    severity: PropTypes.string,
    count: PropTypes.number,
    tactic: PropTypes.string,
  }),
  onPlaybookClick: PropTypes.func,
};

export default TechniqueDetailPanel;
