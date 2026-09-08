import React, { useState, useEffect, useRef } from "react";
import PropTypes from "prop-types";
import PlaybookCard from "./PlaybookCard";
import { 
  FaCheck, 
  FaTimes, 
  FaUser, 
  FaExclamationTriangle, 
  FaSpinner,
  FaExchangeAlt,
} from "react-icons/fa";
import "../../Styles/components/PlaybookList.css";

/* ═══════════════════════════════════════════════════════════════
   Local Helpers for Severity & Status Normalization
   ═══════════════════════════════════════════════════════════════ */

const TECHNIQUE_SEVERITIES = {
  "T1003.001": "critical",
  "T1021.002": "high",
  "T1059.001": "high",
  "T1071.004": "medium",
  "T1053.005": "low",
};

const getPlaybookSeverity = (pb) => {
  if (pb.technique_id && TECHNIQUE_SEVERITIES[pb.technique_id]) {
    return TECHNIQUE_SEVERITIES[pb.technique_id];
  }
  const score = pb.threat_score || 0;
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
};

const getNormalizedStatus = (status) => {
  const s = status ? status.toLowerCase() : "";
  if (s === "pending") return "draft";
  if (s === "exported") return "approved";
  return s; // "approved" or "rejected"
};

/**
 * PlaybookList - Manages multi-selection states of playbooks,
 * renders the header checkbox toggle, and displays a floating
 * action toolbar for batch approvals, rejections, and side-by-side comparison.
 */
const PlaybookList = ({
  playbooks = [],
  onPlaybookClick,
  onCompare,
  refreshData,
  addToast,
}) => {
  const [selectedIds, setSelectedIds] = useState([]);
  const [confirmAction, setConfirmAction] = useState(null); // "approve" | "reject" | null
  const [analystName, setAnalystName] = useState("admin");
  const [loading, setLoading] = useState(false);

  const selectAllRef = useRef(null);

  // Retrieve logged-in analyst name from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem("admin_user");
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.username) {
          setAnalystName(parsed.username);
        }
      }
    } catch {
      // Ignore localStorage read errors
    }
  }, []);

  // Reset selection when playbook list updates (e.g. tab or page changes)
  useEffect(() => {
    setSelectedIds([]);
  }, [playbooks]);

  const isAllSelected = playbooks.length > 0 && selectedIds.length === playbooks.length;
  const isSomeSelected = selectedIds.length > 0 && selectedIds.length < playbooks.length;

  // Set indeterminate state on select-all checkbox
  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = isSomeSelected;
    }
  }, [isSomeSelected]);

  const handleSelectAllChange = () => {
    if (isAllSelected) {
      setSelectedIds([]);
    } else {
      setSelectedIds(playbooks.map((pb) => pb.id));
    }
  };

  const handleSelectOne = (id, checked) => {
    if (checked) {
      setSelectedIds((prev) => [...prev, id]);
    } else {
      setSelectedIds((prev) => prev.filter((item) => item !== id));
    }
  };

  const handleConfirmBatchAction = async () => {
    setLoading(true);
    const endpoint = `/api/sentinel/playbooks/batch/${confirmAction}`;
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          playbook_ids: selectedIds,
          reviewed_by: analystName.trim() || "admin",
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || `Failed to batch ${confirmAction} playbooks.`);
      }

      const successfulCount = data.results?.successful?.length || 0;
      const failedCount = data.results?.failed?.length || 0;

      if (addToast) {
        if (failedCount > 0) {
          addToast({
            type: "warning",
            title: "Batch Action Partially Completed",
            message: `Successfully processed ${successfulCount} playbooks. ${failedCount} failed.`,
            duration: 6000,
          });
        } else {
          addToast({
            type: "success",
            title: "Batch Action Completed",
            message: `Successfully processed ${successfulCount} playbooks.`,
            duration: 4000,
          });
        }
      }

      setConfirmAction(null);
      setSelectedIds([]);
      if (refreshData) {
        await refreshData();
      }
    } catch (err) {
      if (addToast) {
        addToast({
          type: "error",
          title: "Batch Action Failed",
          message: err.message || `An error occurred during batch ${confirmAction}.`,
          duration: 6000,
        });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="playbook-list-container">
      {/* ── List Header Toolbar ── */}
      {playbooks.length > 0 && (
        <div className="playbook-list-header hud-font">
          <div className="header-select-all-group">
            <label className="select-all-label">
              <input
                type="checkbox"
                ref={selectAllRef}
                checked={isAllSelected}
                onChange={handleSelectAllChange}
                disabled={loading}
                className="playbook-list-header-checkbox"
                aria-label="Select all playbooks"
              />
              <span className="select-all-text">
                {isAllSelected ? "DESELECT ALL" : "SELECT ALL"} ({playbooks.length} VISIBLE)
              </span>
            </label>
          </div>
          {selectedIds.length > 0 && (
            <div className="header-selection-badge">
              <span className="selection-badge-glow"></span>
              {selectedIds.length} SELECTED
            </div>
          )}
        </div>
      )}

      {/* ── Playbook Grid ── */}
      <div className="sentinel-playbook-grid">
        {playbooks.map((pb) => (
          <PlaybookCard
            key={pb.id}
            title={pb.playbook_name || "Untitled Playbook"}
            severity={getPlaybookSeverity(pb)}
            technique={pb.technique_id || "T0000"}
            status={getNormalizedStatus(pb.status)}
            date={pb.created_at ? pb.created_at.substring(0, 10) : "—"}
            eventCount={Math.floor((pb.threat_score || 50) * 1.5) || 1}
            onClick={() => onPlaybookClick && onPlaybookClick(pb)}
            selectable={true}
            selected={selectedIds.includes(pb.id)}
            onSelect={(checked) => handleSelectOne(pb.id, checked)}
            disabled={loading}
          />
        ))}
      </div>

      {/* ── Floating Batch Action Toolbar ── */}
      {selectedIds.length > 0 && (
        <div className="floating-batch-toolbar hud-font">
          <div className="toolbar-glow"></div>
          <div className="toolbar-corner top-left"></div>
          <div className="toolbar-corner bottom-right"></div>
          <div className="toolbar-content">
            <span className="toolbar-selected-count">
              <span className="count-number">{selectedIds.length}</span> PLAYBOOKS SELECTED
            </span>
            <div className="toolbar-actions">
              {selectedIds.length === 2 && (
                <button
                  className="toolbar-btn btn-batch-compare"
                  onClick={() => onCompare && onCompare(selectedIds[0], selectedIds[1])}
                  style={{
                    backgroundColor: "rgba(56, 189, 248, 0.2)",
                    borderColor: "rgba(56, 189, 248, 0.6)",
                    color: "#38bdf8",
                  }}
                >
                  <FaExchangeAlt className="btn-icon" />
                  Compare Playbooks (2)
                </button>
              )}
              <button 
                className="toolbar-btn btn-batch-approve"
                onClick={() => setConfirmAction("approve")}
              >
                <FaCheck className="btn-icon" />
                Batch Approve
              </button>
              <button 
                className="toolbar-btn btn-batch-reject"
                onClick={() => setConfirmAction("reject")}
              >
                <FaTimes className="btn-icon" />
                Batch Reject
              </button>
              <button 
                className="toolbar-btn btn-batch-cancel"
                onClick={() => setSelectedIds([])}
              >
                Clear Selection
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Confirmation Modal ── */}
      {confirmAction && (
        <div className="confirm-modal-overlay" onClick={() => !loading && setConfirmAction(null)}>
          <div
            className={`confirm-modal-card pro-card batch-confirm-card ${confirmAction}-card`}
            onClick={(e) => e.stopPropagation()}
          >
            {/* HUD border corners */}
            <div className="hud-corner top-left"></div>
            <div className="hud-corner top-right"></div>
            <div className="hud-corner bottom-left"></div>
            <div className="hud-corner bottom-right"></div>

            <div className="confirm-modal-header">
              <FaExclamationTriangle className="confirm-warn-icon" />
              <h3>Confirm Batch {confirmAction === "approve" ? "Approval" : "Rejection"}</h3>
            </div>

            <div className="confirm-modal-body">
              <p>
                Are you sure you want to{" "}
                <strong className={confirmAction === "approve" ? "text-success" : "text-danger"}>
                  {confirmAction === "approve" ? "APPROVE" : "REJECT"}
                </strong>{" "}
                the <strong>{selectedIds.length}</strong> selected playbooks?
              </p>
              <p className="confirm-desc">
                {confirmAction === "approve"
                  ? "Approved playbooks will be marked ready for automated deployment across all active honeypots."
                  : "Rejected playbooks will be marked inactive and excluded from execution pipelines."}
              </p>

              {/* Analyst verification */}
              <div className="analyst-input-group">
                <label htmlFor="batch-analyst-name-input">
                  <FaUser className="input-icon" /> ANALYST NAME
                </label>
                <input
                  id="batch-analyst-name-input"
                  type="text"
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                  maxLength={128}
                  placeholder="analyst"
                  disabled={loading}
                />
              </div>
            </div>

            <div className="confirm-modal-footer">
              <button
                className="btn-cancel"
                onClick={() => setConfirmAction(null)}
                disabled={loading}
                type="button"
              >
                Cancel
              </button>
              <button
                className={confirmAction === "approve" ? "btn-confirm-approve" : "btn-confirm-reject"}
                onClick={handleConfirmBatchAction}
                disabled={loading || !analystName.trim()}
                type="button"
              >
                {loading ? <FaSpinner className="btn-spinner" style={{ marginRight: "0.5rem" }} /> : null}
                {loading ? "Processing..." : `Confirm Batch ${confirmAction === "approve" ? "Approve" : "Reject"}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

PlaybookList.propTypes = {
  playbooks: PropTypes.array,
  onPlaybookClick: PropTypes.func,
  onCompare: PropTypes.func,
  refreshData: PropTypes.func,
  addToast: PropTypes.func,
};

export default PlaybookList;
