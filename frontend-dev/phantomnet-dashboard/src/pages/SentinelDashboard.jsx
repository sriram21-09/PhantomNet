import React, { useState, useEffect, useMemo, useCallback } from "react";
import { FaShieldAlt, FaTerminal, FaSortAmountDown, FaSortAmountUp, FaPlus, FaSync } from "react-icons/fa";
import PlaybookCard from "../components/sentinel/PlaybookCard";
import MitreTag from "../components/sentinel/MitreTag";
import MitreMatrix from "../components/sentinel/MitreMatrix";
import RulePreview from "../components/sentinel/RulePreview";
import PlaybookViewer from "../components/sentinel/PlaybookViewer";
import ToastContainer, { useToast } from "../components/ui/ToastNotification";
import "../Styles/pages/SentinelDashboard.css";

/* Sample playbooks to preview PlaybookCard variants */



/* Sample MITRE techniques to showcase MitreTag variants */
const sampleTechniques = [
  { techniqueId: "T1110.001", techniqueName: "Password Guessing",         tactic: "credential-access" },
  { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment",  tactic: "initial-access" },
  { techniqueId: "T1059.001", techniqueName: "PowerShell",                tactic: "execution" },
  { techniqueId: "T1053.005", techniqueName: "Scheduled Task",            tactic: "persistence" },
  { techniqueId: "T1083",     techniqueName: "File and Directory Discovery", tactic: "discovery" },
  { techniqueId: "T1021.002", techniqueName: "SMB/Windows Admin Shares",  tactic: "lateral-movement" },
  { techniqueId: "T1071.004", techniqueName: "DNS",                       tactic: "command-and-control" },
  { techniqueId: "T1048.003", techniqueName: "Exfiltration Over C2",      tactic: "exfiltration" },
  { techniqueId: "T1070.004", techniqueName: "File Deletion",             tactic: "defense-evasion" },
  { techniqueId: "T1068",     techniqueName: "Exploitation for Privilege Escalation", tactic: "privilege-escalation" },
  { techniqueId: "T1486",     techniqueName: "Data Encrypted for Impact", tactic: "impact" },
  { techniqueId: "T1119",     techniqueName: "Automated Collection",      tactic: "collection" },
];


/* Sample detection rules */
const sampleSnortRule = `alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT Possible SMB Brute Force"; flow:to_server,established; content:"|ff|SMB"; depth:4; content:"|73 00 00 00|"; distance:0; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:2024001; rev:3;)

# Secondary detection for lateral movement
alert tcp $HOME_NET any -> $HOME_NET 135 (msg:"INTERNAL Lateral Movement via DCOM"; flow:to_server,established; content:"|05|"; depth:1; content:"|0b|"; distance:1; within:1; classtype:attempted-admin; sid:2024002; rev:1;)`;

const sampleSigmaRule = `title: Suspicious PowerShell Download Cradle
id: 3b6ab547-1c3b-4a85-bf71-3246a1e8e1d5
status: experimental
description: Detects suspicious PowerShell download cradle patterns
author: PhantomNet Sentinel
date: 2026/06/18
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'powershell'
      - 'downloadstring'
  condition: selection
falsepositives:
  - Legitimate admin scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001`;

/* ═══════════════════════════════════════════════════════════════
   Sort Configuration
   ═══════════════════════════════════════════════════════════════ */

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
const STATUS_ORDER = { draft: 1, approved: 2, rejected: 3 };

const SORT_COLUMNS = [
  { key: "date", label: "Date" },
  { key: "severity", label: "Severity" },
  { key: "status", label: "Status" },
];

// Map playbooks technique/score to UI severity
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

const SentinelDashboard = () => {
  const [playbooks, setPlaybooks] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("all");

  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [isViewerOpen, setIsViewerOpen] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);

  const [techniques, setTechniques] = useState(sampleTechniques);
  const [matrixData, setMatrixData] = useState(null);
  const [aiStatus, setAiStatus] = useState("checking");

  /* ── Pagination State ── */
  const [currentPage, setCurrentPage] = useState(1);
  const [perPage, setPerPage] = useState(12);
  const [totalCount, setTotalCount] = useState(0);

  /* ── Sort State ── */
  const [sortColumn, setSortColumn] = useState("date");
  const [sortDirection, setSortDirection] = useState("desc"); // newest first

  /* ── Toast Notifications ── */
  const { toasts, addToast, removeToast } = useToast();

  const fetchData = async (page = currentPage, pageSize = perPage, tab = activeTab) => {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch playbooks list
      let backendStatus = "";
      if (tab === "draft") backendStatus = "pending";
      else if (tab === "approved") backendStatus = "approved";
      else if (tab === "rejected") backendStatus = "rejected";

      const url = `/api/sentinel/playbooks?page=${page}&per_page=${pageSize}${backendStatus ? `&status=${backendStatus}` : ""}`;
      const playbooksRes = await fetch(url);
      const playbooksData = await playbooksRes.json();
      if (!playbooksRes.ok) {
        throw new Error(playbooksData.detail || "Failed to load playbooks from server");
      }
      setPlaybooks(playbooksData.playbooks || []);
      setTotalCount(playbooksData.total || 0);

      // 2. Fetch stats
      try {
        const statsRes = await fetch("/api/sentinel/stats");
        const statsData = await statsRes.json();
        if (statsRes.ok && statsData.status === "success") {
          setStats(statsData);
        }
      } catch (statsErr) {
        console.warn("Could not fetch Sentinel stats:", statsErr);
      }

      // 3. Fetch MITRE mappings dynamically
      try {
        const techRes = await fetch("/api/sentinel/mitre/mapping");
        const techData = await techRes.json();
        if (techRes.ok && techData.status === "success" && techData.mappings) {
          const mapped = techData.mappings.map((m) => ({
            techniqueId: m.technique_id,
            techniqueName: m.technique_name,
            tactic: m.tactic,
          }));
          // Dedup
          const unique = Array.from(
            new Map(mapped.map((item) => [item.techniqueId, item])).values()
          );
          if (unique.length > 0) {
            setTechniques(unique);
          }
        }
      } catch (techErr) {
        console.warn("Could not fetch MITRE mappings dynamically, using fallback:", techErr);
      }

      // 4. Fetch LLM pipeline status
      try {
        const llmRes = await fetch("/api/sentinel/llm/status");
        const llmData = await llmRes.json();
        if (llmRes.ok && llmData.status === "success") {
          setAiStatus(llmData.llm_status || "offline");
        } else {
          setAiStatus("offline");
        }
      } catch (llmErr) {
        console.warn("Could not fetch Sentinel LLM status:", llmErr);
        setAiStatus("offline");
      }

      // 5. Fetch MITRE ATT&CK Matrix Data
      try {
        const mRes = await fetch("/api/sentinel/mitre/matrix");
        const mData = await mRes.json();
        if (mRes.ok) {
          setMatrixData(mData);
        }
      } catch (mErr) {
        console.warn("Could not fetch MITRE ATT&CK Matrix data:", mErr);
      }

    } catch (err) {
      console.error("Dashboard connection error:", err);
      setError(err.message || "Failed to connect to the Sentinel Security Service");
      addToast({
        type: "error",
        title: "Connection Failed",
        message: err.message || "Failed to connect to the Sentinel Security Service",
        duration: 6000,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData(currentPage, perPage, activeTab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentPage, perPage, activeTab]);

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setCurrentPage(1);
  };

  // Normalization logic
  const getNormalizedStatus = (status) => {
    const s = status ? status.toLowerCase() : "";
    if (s === "pending") return "draft";
    if (s === "exported") return "approved";
    return s; // "approved" or "rejected"
  };

  // Filter playbooks based on tab selection
  const filteredPlaybooks = useMemo(() => {
    return playbooks;
  }, [playbooks]);

  /* ── Sort toggle handler ── */
  const handleSortClick = useCallback((column) => {
    if (sortColumn === column) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortDirection(column === "date" ? "desc" : "asc");
      setSortColumn(column);
    }
  }, [sortColumn]);

  /* ── Sorted playbooks ── */
  const sortedPlaybooks = useMemo(() => {
    const list = [...filteredPlaybooks];
    const dir = sortDirection === "asc" ? 1 : -1;

    list.sort((a, b) => {
      switch (sortColumn) {
        case "date": {
          const da = a.created_at || "";
          const db = b.created_at || "";
          return dir * da.localeCompare(db);
        }
        case "severity": {
          const sa = SEVERITY_ORDER[getPlaybookSeverity(a)] || 0;
          const sb = SEVERITY_ORDER[getPlaybookSeverity(b)] || 0;
          return dir * (sa - sb);
        }
        case "status": {
          const sta = STATUS_ORDER[getNormalizedStatus(a.status)] || 0;
          const stb = STATUS_ORDER[getNormalizedStatus(b.status)] || 0;
          return dir * (sta - stb);
        }
        default:
          return 0;
      }
    });

    return list;
  }, [filteredPlaybooks, sortColumn, sortDirection]);

  // Compute tab counts
  const counts = useMemo(() => {
    if (stats) {
      return {
        all: stats.total_playbooks || 0,
        draft: stats.pending || 0,
        approved: (stats.approved || 0) + (stats.exported || 0),
        rejected: stats.rejected || 0,
      };
    }
    // Fallback if stats is not loaded yet (e.g. offline or first load)
    let draft = 0;
    let approved = 0;
    let rejected = 0;
    playbooks.forEach((pb) => {
      const s = getNormalizedStatus(pb.status);
      if (s === "draft") draft++;
      else if (s === "approved") approved++;
      else if (s === "rejected") rejected++;
    });
    return {
      all: playbooks.length,
      draft,
      approved,
      rejected,
    };
  }, [stats, playbooks]);



  const handleCardClick = async (pb) => {
    // Open immediately with summary props to provide instant response
    setSelectedPlaybook({
      ...pb,
      playbook_content: "",
      snort_rule: "",
      sigma_rule: "",
    });
    setIsViewerOpen(true);
    setLoadingDetails(true);

    try {
      const response = await fetch(`/api/sentinel/playbooks/${pb.id}`);
      const data = await response.json();
      if (response.ok && data.status === "success") {
        setSelectedPlaybook(data.playbook);
      } else {
        console.error("Failed to load playbook details:", data.detail);
        addToast({
          type: "error",
          title: "Playbook Load Failed",
          message: data.detail || "Failed to load playbook details",
        });
      }
    } catch (err) {
      console.error("Failed to fetch playbook details:", err);
      addToast({
        type: "error",
        title: "Network Error",
        message: "Could not reach the Sentinel API. Please check your connection.",
      });
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleStatusChange = (newStatus) => {
    // 1. Update playbooks list
    setPlaybooks((prev) =>
      prev.map((pb) =>
        pb.id === selectedPlaybook.id ? { ...pb, status: newStatus } : pb
      )
    );
    // 2. Update stats count
    setStats((prev) => {
      if (!prev) return prev;
      const oldStatus = selectedPlaybook.status;
      const countsUpdate = { ...prev };
      
      const oldNorm = getNormalizedStatus(oldStatus);
      const newNorm = getNormalizedStatus(newStatus);
      
      if (oldNorm !== newNorm) {
        if (oldNorm === "draft" && countsUpdate.pending > 0) countsUpdate.pending--;
        else if (oldNorm === "approved" && countsUpdate.approved > 0) countsUpdate.approved--;
        else if (oldNorm === "rejected" && countsUpdate.rejected > 0) countsUpdate.rejected--;

        if (newNorm === "draft") countsUpdate.pending++;
        else if (newNorm === "approved") countsUpdate.approved++;
        else if (newNorm === "rejected") countsUpdate.rejected++;
      }
      return countsUpdate;
    });
    // 3. Update selectedPlaybook details status so modal re-renders
    setSelectedPlaybook((prev) =>
      prev ? { ...prev, status: newStatus } : null
    );
  };

  const handleLLMNarrativeUpdate = (playbookId, newNarrative) => {
    setPlaybooks((prev) =>
      prev.map((pb) =>
        pb.id === playbookId ? { ...pb, llm_narrative: newNarrative } : pb
      )
    );
    setSelectedPlaybook((prev) =>
      prev && prev.id === playbookId ? { ...prev, llm_narrative: newNarrative } : prev
    );
    addToast({
      type: "success",
      title: "Narrative Updated",
      message: "AI narrative summary refreshed successfully.",
    });
  };

  return (
    <div className="sentinel-wrapper">
      {/* Header */}
      <div className="sentinel-header">
        <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "0.75rem" }}>
          <div className="sentinel-badge hud-font">SENTINEL_ENGINE_V1.0</div>
          <div 
            className={`sentinel-badge hud-font sentinel-ai-status-badge ${aiStatus === "online" ? "ai-online" : "ai-offline"}`}
            style={{ cursor: "pointer", userSelect: "none" }}
            onClick={() => {
              setAiStatus(prev => prev === "online" ? "offline" : "online");
            }}
            title="Click to toggle mock status"
          >
            AI: {aiStatus === "online" ? "Online" : "Offline"}
          </div>
        </div>
        <h1 className="sentinel-title">Sentinel Dashboard</h1>
        <p className="sentinel-subtitle">
          AUTONOMOUS THREAT DETECTION &amp; RESPONSE COMMAND CENTER
        </p>
      </div>

      {/* Live Status Bar */}
      <div className="sentinel-status-bar">
        <div className="status-item">
          <span className="status-dot-live"></span>
          <span className="status-label">ENGINE STATUS:</span>
          <span>ONLINE</span>
        </div>
        <div className="status-item">
          <span className="status-dot-live" style={{
            background: aiStatus === "online" ? "#10b981" : aiStatus === "checking" ? "#fb923c" : "#ef4444"
          }}></span>
          <span className="status-label">AI PIPELINE:</span>
          <span style={{ color: aiStatus === "online" ? "#34d399" : aiStatus === "checking" ? "#fb923c" : "#f87171" }}>
            {aiStatus.toUpperCase()}
          </span>
        </div>
        <div className="status-item">
          <span className="status-label">UPTIME:</span>
          <span>ONLINE</span>
        </div>
        <div className="status-item">
          <span className="status-label">RULES LOADED:</span>
          <span>{stats?.total_playbooks ?? playbooks.length}</span>
        </div>
        <div className="status-item">
          <span className="status-label">LAST SCAN:</span>
          <span>
            {stats?.latest_playbook_at
              ? new Date(stats.latest_playbook_at).toLocaleTimeString()
              : "—"}
          </span>
        </div>
      </div>

      {/* MITRE ATT&CK Techniques */}
      <div className="sentinel-content" style={{ marginBottom: "2rem" }}>
        <div className="sentinel-section-header">
          <h2 className="sentinel-section-title">ATT&amp;CK Coverage</h2>
          <span className="sentinel-section-count hud-font">
            {techniques.length} TECHNIQUES
          </span>
        </div>
        <div className="sentinel-mitre-grid">
          {techniques.map((t, idx) => (
            <MitreTag key={idx} {...t} />
          ))}
        </div>
        <div style={{ marginTop: "1.5rem" }}>
          <MitreMatrix techniquesData={matrixData} />
        </div>
      </div>

      {/* Rule Preview */}
      <div className="sentinel-content" style={{ marginBottom: "2rem" }}>
        <div className="sentinel-section-header">
          <h2 className="sentinel-section-title">Detection Rules</h2>
          <span className="sentinel-section-count hud-font">SNORT / SIGMA</span>
        </div>
        <RulePreview snortRule={sampleSnortRule} sigmaRule={sampleSigmaRule} />
      </div>

      {/* Playbook Section */}
      <div className="sentinel-content">
        <div className="sentinel-section-header">
          <h2 className="sentinel-section-title">Generated Playbooks</h2>
          <span className="sentinel-section-count hud-font">
            {filteredPlaybooks.length} PLAYBOOKS
          </span>
        </div>

        {/* Filter Tabs */}
        <div className="sentinel-tabs-container hud-font">
          <button
            className={`sentinel-tab-btn ${activeTab === "all" ? "active" : ""}`}
            onClick={() => handleTabChange("all")}
          >
            All <span className="tab-count">{counts.all}</span>
          </button>
          <button
            className={`sentinel-tab-btn ${activeTab === "draft" ? "active" : ""}`}
            onClick={() => handleTabChange("draft")}
          >
            Draft <span className="tab-count">{counts.draft}</span>
          </button>
          <button
            className={`sentinel-tab-btn ${activeTab === "approved" ? "active" : ""}`}
            onClick={() => handleTabChange("approved")}
          >
            Approved <span className="tab-count">{counts.approved}</span>
          </button>
          <button
            className={`sentinel-tab-btn ${activeTab === "rejected" ? "active" : ""}`}
            onClick={() => handleTabChange("rejected")}
          >
            Rejected <span className="tab-count">{counts.rejected}</span>
          </button>
        </div>

        {/* ── Sort Header Bar ── */}
        {!loading && !error && filteredPlaybooks.length > 0 && (
          <div className="sentinel-sort-bar hud-font">
            <span className="sort-bar-label">SORT BY:</span>
            {SORT_COLUMNS.map((col) => {
              const isActive = sortColumn === col.key;
              return (
                <button
                  key={col.key}
                  className={`sort-header-btn ${isActive ? "active" : ""}`}
                  onClick={() => handleSortClick(col.key)}
                  title={`Sort by ${col.label}`}
                >
                  {col.label}
                  {isActive && (
                    <span className="sort-arrow">
                      {sortDirection === "asc" ? (
                        <FaSortAmountUp className="sort-arrow-icon" />
                      ) : (
                        <FaSortAmountDown className="sort-arrow-icon" />
                      )}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}

        {/* Display Grid States */}
        {loading ? (
          <div className="sentinel-playbook-grid">
            {Array.from({ length: 6 }).map((_, idx) => (
              <div key={idx} className="playbook-skeleton-card">
                <div className="playbook-skeleton-glow"></div>
              </div>
            ))}
          </div>
        ) : error ? (
          <div className="sentinel-error-state hud-font">
            <FaTerminal className="error-icon" />
            <h3>System Connection Failure</h3>
            <p>{error}</p>
            <button onClick={fetchData} className="retry-btn">
              <FaSync style={{ marginRight: "0.5rem" }} />
              Retry Connection
            </button>
          </div>
        ) : filteredPlaybooks.length === 0 ? (
          <div className="sentinel-empty-state">
            <div className="sentinel-empty-icon">
              <FaShieldAlt />
            </div>
            <h3 className="sentinel-empty-title">No Playbooks Found</h3>
            <p className="sentinel-empty-description">
              {activeTab === "all"
                ? "No response playbooks have been generated yet. Trigger the Sentinel pipeline to create your first automated playbook."
                : `No playbooks with status "${activeTab.toUpperCase()}" found.`}
            </p>
            {activeTab === "all" ? (
              <button className="sentinel-cta-btn" onClick={fetchData}>
                <FaPlus style={{ marginRight: "0.5rem" }} />
                Refresh Playbooks
              </button>
            ) : (
              <button
                className="sentinel-cta-btn"
                onClick={() => setActiveTab("all")}
              >
                View All Playbooks
              </button>
            )}
          </div>
        ) : (
          <div className="sentinel-playbook-grid">
            {sortedPlaybooks.map((pb) => (
              <PlaybookCard
                key={pb.id}
                title={pb.playbook_name || "Untitled Playbook"}
                severity={getPlaybookSeverity(pb)}
                technique={pb.technique_id || "T0000"}
                status={getNormalizedStatus(pb.status)}
                date={pb.created_at ? pb.created_at.substring(0, 10) : "—"}
                eventCount={Math.floor((pb.threat_score || 50) * 1.5) || 1}
                onClick={() => handleCardClick(pb)}
              />
            ))}
          </div>
        )}

        {/* Pagination Controls */}
        {!loading && !error && totalCount > 0 && (
          <div className="sentinel-pagination-container hud-font">
            <div className="pagination-info">
              Showing <span className="highlight">{(currentPage - 1) * perPage + 1}</span>–
              <span className="highlight">{Math.min(currentPage * perPage, totalCount)}</span> of{" "}
              <span className="highlight">{totalCount}</span> playbooks
            </div>
            
            <div className="pagination-controls">
              <button
                className="pag-btn"
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
              >
                PREV
              </button>
              
              {Array.from({ length: Math.ceil(totalCount / perPage) }).map((_, idx) => {
                const pageNum = idx + 1;
                const isNearCurrent = Math.abs(currentPage - pageNum) <= 2;
                const isFirstOrLast = pageNum === 1 || pageNum === Math.ceil(totalCount / perPage);
                
                if (isNearCurrent || isFirstOrLast) {
                  return (
                    <button
                      key={pageNum}
                      className={`pag-btn ${currentPage === pageNum ? "active" : ""}`}
                      onClick={() => setCurrentPage(pageNum)}
                    >
                      {pageNum}
                    </button>
                  );
                } else if (
                  (pageNum === 2 && currentPage > 4) ||
                  (pageNum === Math.ceil(totalCount / perPage) - 1 && currentPage < Math.ceil(totalCount / perPage) - 3)
                ) {
                  return <span key={pageNum} className="pag-ellipsis">...</span>;
                }
                return null;
              })}

              <button
                className="pag-btn"
                onClick={() => setCurrentPage((p) => Math.min(Math.ceil(totalCount / perPage), p + 1))}
                disabled={currentPage === Math.ceil(totalCount / perPage)}
              >
                NEXT
              </button>
            </div>
            
            <div className="pagination-size-selector">
              <span>ITEMS PER PAGE:</span>
              <select
                value={perPage}
                onChange={(e) => {
                  setPerPage(Number(e.target.value));
                  setCurrentPage(1);
                }}
              >
                <option value={6}>6</option>
                <option value={12}>12</option>
                <option value={24}>24</option>
                <option value={48}>48</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Playbook Viewer Modal */}
      {selectedPlaybook && (
        <PlaybookViewer
          key={`${selectedPlaybook.id}-${isViewerOpen}`}
          isOpen={isViewerOpen}
          onClose={() => setIsViewerOpen(false)}
          id={selectedPlaybook.id}
          status={selectedPlaybook.status}
          onStatusChange={handleStatusChange}
          isLoading={loadingDetails}
          title={selectedPlaybook.playbook_name || "Untitled Playbook"}
          severity={getPlaybookSeverity(selectedPlaybook)}
          technique={selectedPlaybook.technique_id || "T0000"}
          date={selectedPlaybook.created_at ? selectedPlaybook.created_at.substring(0, 10) : "—"}
          playbook_content={selectedPlaybook.playbook_content}
          snortRule={selectedPlaybook.snort_rule}
          sigmaRule={selectedPlaybook.sigma_rule}
          llm_narrative={selectedPlaybook.llm_narrative}
          onLLMNarrativeUpdate={handleLLMNarrativeUpdate}
        />
      )}

      {/* ── Toast Notifications ── */}
      <ToastContainer toasts={toasts} onDismiss={removeToast} />
    </div>
  );
};

export default SentinelDashboard;

