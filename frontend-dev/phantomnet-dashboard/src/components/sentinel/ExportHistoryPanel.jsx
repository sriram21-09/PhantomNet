import React, { useState, useEffect, useCallback } from "react";
import {
  FaHistory,
  FaFilePdf,
  FaFileCode,
  FaMarkdown,
  FaFileArchive,
  FaDownload,
  FaSync,
  FaUserCircle,
  FaClock,
  FaExclamationCircle,
} from "react-icons/fa";

/**
 * Helper to parse export details JSON string or object
 */
const parseDetails = (details) => {
  if (!details) return {};
  if (typeof details === "object") return details;
  try {
    return JSON.parse(details);
  } catch {
    return { raw: details };
  }
};

/**
 * Format badge styling and icon helper
 */
const getFormatBadgeInfo = (fmt) => {
  const normalized = (fmt || "").toLowerCase();
  if (normalized.includes("pdf")) {
    return {
      label: "PDF",
      icon: FaFilePdf,
      bg: "rgba(239, 68, 68, 0.15)",
      color: "#ef4444",
      border: "rgba(239, 68, 68, 0.3)",
    };
  }
  if (normalized.includes("stix")) {
    return {
      label: "STIX 2.1",
      icon: FaFileCode,
      bg: "rgba(168, 85, 247, 0.15)",
      color: "#a855f7",
      border: "rgba(168, 85, 247, 0.3)",
    };
  }
  if (normalized.includes("zip") || normalized.includes("archive")) {
    return {
      label: "ZIP",
      icon: FaFileArchive,
      bg: "rgba(245, 158, 11, 0.15)",
      color: "#f59e0b",
      border: "rgba(245, 158, 11, 0.3)",
    };
  }
  if (normalized.includes("json")) {
    return {
      label: "JSON",
      icon: FaFileCode,
      bg: "rgba(6, 182, 212, 0.15)",
      color: "#06b6d4",
      border: "rgba(6, 182, 212, 0.3)",
    };
  }
  if (normalized.includes("md") || normalized.includes("markdown")) {
    return {
      label: "MARKDOWN",
      icon: FaMarkdown,
      bg: "rgba(59, 130, 246, 0.15)",
      color: "#3b82f6",
      border: "rgba(59, 130, 246, 0.3)",
    };
  }
  return {
    label: (fmt || "FILE").toUpperCase(),
    icon: FaDownload,
    bg: "rgba(148, 163, 184, 0.15)",
    color: "#94a3b8",
    border: "rgba(148, 163, 184, 0.3)",
  };
};

/**
 * ExportHistoryPanel Component
 * Displays playbook export audit trail (format, user, timestamp) and quick re-download links.
 */
export default function ExportHistoryPanel({
  playbookId,
  playbookCode,
  refreshTrigger = 0,
  onReDownload,
}) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [downloadingId, setDownloadingId] = useState(null);

  const fetchExportHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Primary route: GET /api/sentinel/playbooks/{id}/export-history OR global audit-logs
      const url = playbookId
        ? `/api/sentinel/playbooks/${playbookId}/export-history`
        : `/api/sentinel/audit-logs?action=export`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setLogs(data.export_history || data.logs || []);
      } else {
        // Fallback: GET /api/sentinel/audit-logs
        const fallbackUrl = playbookId
          ? `/api/sentinel/audit-logs?playbook_id=${playbookId}&action=export`
          : `/api/sentinel/audit-logs`;
        const fallbackRes = await fetch(fallbackUrl);
        if (fallbackRes.ok) {
          const fallbackData = await fallbackRes.json();
          setLogs(fallbackData.logs || []);
        } else {
          setError("Failed to load export history log.");
        }
      }
    } catch (err) {
      console.error("Failed to fetch export history:", err);
      setError("Network error fetching audit logs.");
    } finally {
      setLoading(false);
    }
  }, [playbookId]);

  useEffect(() => {
    fetchExportHistory();
  }, [fetchExportHistory, refreshTrigger]);

  const handleQuickReDownload = async (log) => {
    const details = parseDetails(log.details);
    const fmt = (details.format || "json").toLowerCase();
    const logId = log.id;

    if (onReDownload) {
      onReDownload(fmt, log);
      return;
    }

    setDownloadingId(logId);
    try {
      let downloadUrl = `/api/sentinel/playbooks/${playbookId}/export?format=${fmt}`;
      if (fmt === "pdf") {
        downloadUrl = `/api/sentinel/playbooks/${playbookId}/export/pdf`;
      } else if (fmt === "zip") {
        downloadUrl = `/api/sentinel/rules/export-all`;
      }

      const res = await fetch(downloadUrl, { method: fmt === "zip" ? "GET" : "POST" });
      if (!res.ok) throw new Error(`Export failed with HTTP ${res.status}`);

      const blob = await res.blob();
      const contentDisp = res.headers.get("Content-Disposition");
      let fileName = details.filename || `${playbookCode || "playbook"}.${fmt}`;
      if (contentDisp && contentDisp.includes("filename=")) {
        const match = contentDisp.match(/filename=["']?([^"';]+)["']?/);
        if (match && match[1]) fileName = match[1];
      }

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      // Refresh log list to record new download action
      setTimeout(fetchExportHistory, 500);
    } catch (err) {
      console.error("Re-download failed:", err);
      alert(`Re-download failed: ${err.message}`);
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="ehp-container">
      {/* Panel Header */}
      <div className="ehp-header">
        <div className="ehp-title">
          <FaHistory className="ehp-title-icon" />
          <span>Export Activity & Audit Log</span>
          {logs.length > 0 && <span className="ehp-count-badge">{logs.length}</span>}
        </div>
        <button
          className="ehp-refresh-btn"
          onClick={fetchExportHistory}
          disabled={loading}
          title="Refresh Export Audit Logs"
        >
          <FaSync className={loading ? "ehp-spin" : ""} />
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div className="ehp-error">
          <FaExclamationCircle />
          <span>{error}</span>
        </div>
      )}

      {/* Content Timeline */}
      {loading && logs.length === 0 ? (
        <div className="ehp-loading">Loading export history...</div>
      ) : logs.length === 0 ? (
        <div className="ehp-empty">
          <p>No exports recorded yet for this playbook.</p>
          <span className="ehp-empty-sub">
            Export in PDF, STIX, JSON, or Markdown format to log activity here.
          </span>
        </div>
      ) : (
        <div className="ehp-timeline">
          {logs.map((log) => {
            const details = parseDetails(log.details);
            const fmt = details.format || "export";
            const badge = getFormatBadgeInfo(fmt);
            const BadgeIcon = badge.icon;
            const logDate = log.timestamp
              ? new Date(log.timestamp).toLocaleString(undefined, {
                  month: "short",
                  day: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                })
              : "Recent";

            return (
              <div key={log.id} className="ehp-timeline-item">
                <div className="ehp-node" style={{ borderColor: badge.color, backgroundColor: badge.bg }}>
                  <BadgeIcon style={{ color: badge.color }} />
                </div>
                <div className="ehp-item-content">
                  <div className="ehp-item-top">
                    <span
                      className="ehp-fmt-badge"
                      style={{
                        backgroundColor: badge.bg,
                        color: badge.color,
                        borderColor: badge.border,
                      }}
                    >
                      {badge.label}
                    </span>
                    <span className="ehp-user">
                      <FaUserCircle className="ehp-icon-sub" /> {log.user || "analyst"}
                    </span>
                    <span className="ehp-time">
                      <FaClock className="ehp-icon-sub" /> {logDate}
                    </span>
                  </div>

                  {details.filename && (
                    <div className="ehp-filename" title={details.filename}>
                      {details.filename}
                    </div>
                  )}

                  <div className="ehp-item-actions">
                    <button
                      className="ehp-redownload-btn"
                      onClick={() => handleQuickReDownload(log)}
                      disabled={downloadingId === log.id}
                      title={`Re-download ${badge.label} file`}
                    >
                      <FaDownload className={downloadingId === log.id ? "ehp-spin" : ""} />
                      <span>{downloadingId === log.id ? "Downloading..." : `Re-download ${badge.label}`}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
