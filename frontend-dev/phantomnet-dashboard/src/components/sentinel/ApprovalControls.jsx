import React, { useState, useEffect } from "react";
import {
  FaCheck,
  FaTimes,
  FaCheckCircle,
  FaTimesCircle,
  FaUser,
  FaExclamationTriangle,
  FaInfoCircle,
  FaSpinner
} from "react-icons/fa";
import "../../Styles/components/ApprovalControls.css";

/**
 * ApprovalControls - Sub-component inside the PlaybookViewer modal footer.
 * Allows analysts to approve or reject playbooks with a confirmation step.
 *
 * @param {number}   playbookId     - Database ID of the playbook
 * @param {string}   status         - Current status (pending, approved, rejected, exported)
 * @param {function} onStatusChange - Parent callback when status successfully updates
 */
const ApprovalControls = ({ playbookId, status, onStatusChange }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [toast, setToast] = useState(null); // { type: "success" | "error", message: string }
  const [confirmType, setConfirmType] = useState(null); // "approve" | "reject" | null
  const [analystName, setAnalystName] = useState("admin");

  // Read current logged-in user from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem("admin_user");
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.username) {
          setAnalystName(parsed.username);
        }
      }
    } catch (err) {
      console.warn("Failed to load admin user from localStorage", err);
    }
  }, []);

  // Auto-clear toast alert after 4 seconds
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  const handleReviewAction = async (action) => {
    setLoading(true);
    setError(null);
    setConfirmType(null);

    const endpoint = `/api/sentinel/playbooks/${playbookId}/${action}`;

    try {
      const response = await fetch(endpoint, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          reviewed_by: analystName.trim() || "admin",
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || `Failed to ${action} playbook`);
      }

      setToast({
        type: "success",
        message: `Playbook successfully ${action === "approve" ? "approved" : "rejected"} by ${analystName}`,
      });

      if (onStatusChange) {
        onStatusChange(action === "approve" ? "approved" : "rejected");
      }
    } catch (err) {
      console.error(err);
      setError(err.message);
      setToast({
        type: "error",
        message: err.message,
      });
    } finally {
      setLoading(false);
    }
  };

  // Map status labels & classes
  const getStatusLabel = () => {
    if (status === "pending") return "Draft";
    return status.charAt(0).toUpperCase() + status.slice(1);
  };

  const getStatusClass = () => {
    if (status === "pending") return "status-draft";
    return `status-${status}`;
  };

  const isPending = status === "pending";
  const isApproved = status === "approved" || status === "exported";
  const isRejected = status === "rejected";

  return (
    <div className="approval-controls-container hud-font">
      {/* ── Status Indicator ── */}
      <div className="approval-status-group">
        <span className="approval-status-label">CURRENT STATUS</span>
        <div className={`playbook-status-badge ${getStatusClass()}`}>
          <span className="status-dot"></span>
          {getStatusLabel()}
        </div>
      </div>

      {/* ── Action Buttons ── */}
      <div className="approval-actions">
        {/* Approve Button */}
        <button
          className={`btn-approve ${isApproved ? "active-approved" : ""} ${loading ? "btn-loading" : ""}`}
          onClick={() => setConfirmType("approve")}
          disabled={loading || isApproved}
          type="button"
          title="Approve this playbook for deployment"
        >
          {loading ? <FaSpinner className="btn-icon btn-spinner" /> : <FaCheck className="btn-icon" />}
          {isApproved ? "Approved" : loading ? "Processing..." : "Approve"}
        </button>

        {/* Reject Button */}
        <button
          className={`btn-reject ${isRejected ? "active-rejected" : ""} ${loading ? "btn-loading" : ""}`}
          onClick={() => setConfirmType("reject")}
          disabled={loading || isRejected}
          type="button"
          title="Reject this playbook"
        >
          {loading ? <FaSpinner className="btn-icon btn-spinner" /> : <FaTimes className="btn-icon" />}
          {isRejected ? "Rejected" : loading ? "Processing..." : "Reject"}
        </button>
      </div>

      {/* ── Confirmation Overlay Modal ── */}
      {confirmType && (
        <div className="confirm-modal-overlay" onClick={() => setConfirmType(null)}>
          <div
            className={`confirm-modal-card pro-card ${confirmType}-card`}
            onClick={(e) => e.stopPropagation()}
          >
            {/* HUD border corners */}
            <div className="hud-corner top-left"></div>
            <div className="hud-corner top-right"></div>
            <div className="hud-corner bottom-left"></div>
            <div className="hud-corner bottom-right"></div>

            <div className="confirm-modal-header">
              <FaExclamationTriangle className="confirm-warn-icon" />
              <h3>Confirm Playbook Action</h3>
            </div>

            <div className="confirm-modal-body">
              <p>
                Are you sure you want to{" "}
                <strong className={confirmType === "approve" ? "text-success" : "text-danger"}>
                  {confirmType === "approve" ? "APPROVE" : "REJECT"}
                </strong>{" "}
                this playbook?
              </p>
              <p className="confirm-desc">
                {confirmType === "approve"
                  ? "Approved playbooks are marked ready for automated deployment and threat mitigation."
                  : "Rejected playbooks are excluded from automation rules and require further investigation."}
              </p>

              {/* Analyst verification */}
              <div className="analyst-input-group">
                <label htmlFor="analyst-name-input">
                  <FaUser className="input-icon" /> ANALYST NAME
                </label>
                <input
                  id="analyst-name-input"
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
                onClick={() => setConfirmType(null)}
                disabled={loading}
                type="button"
              >
                Cancel
              </button>
              <button
                className={confirmType === "approve" ? "btn-confirm-approve" : "btn-confirm-reject"}
                onClick={() => handleReviewAction(confirmType)}
                disabled={loading || !analystName.trim()}
                type="button"
              >
                {loading ? "Processing..." : `Confirm ${confirmType}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Custom Toast Notifications ── */}
      {toast && (
        <div className={`floating-toast toast-${toast.type}`}>
          {toast.type === "success" ? (
            <FaCheckCircle className="toast-icon" />
          ) : (
            <FaTimesCircle className="toast-icon" />
          )}
          <span className="toast-text">{toast.message}</span>
          <button className="toast-close" onClick={() => setToast(null)}>
            <FaTimes />
          </button>
        </div>
      )}
    </div>
  );
};

export default ApprovalControls;
