import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { FaTerminal, FaGlobe, FaEnvelope, FaServer } from "react-icons/fa";
import {
  RefreshCw,
  Search,
  AlertTriangle,
  ExternalLink,
  X,
  SlidersHorizontal,
  ShieldCheck,
  Radio,
  Server,
  Activity,
  CheckCircle2,
  XCircle,
  Network,
} from "lucide-react";
import "../Styles/pages/Honeypots.css";

const formatLastSeen = (lastSeen) => {
  if (!lastSeen || lastSeen === "Never") return "Never";
  try {
    const lastSeenDate = new Date(lastSeen);
    if (isNaN(lastSeenDate.getTime())) return "Never";
    const now = new Date();
    const diffMs = now.getTime() - lastSeenDate.getTime();
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 10) return "Just now";
    if (diffSecs < 60) return `${diffSecs}s ago`;
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return lastSeenDate.toLocaleDateString();
  } catch {
    return "Never";
  }
};

const PROTOCOL_ICONS = {
  SSH: FaTerminal,
  HTTP: FaGlobe,
  FTP: FaServer,
  SMTP: FaEnvelope,
};

// Skeleton Card for zero-layout-shift loading state
const HoneypotCardSkeleton = () => (
  <div className="honeypot-card skeleton" aria-hidden="true">
    <div className="card-top-row">
      <div className="skeleton-pill short"></div>
      <div className="skeleton-pill tiny"></div>
    </div>
    <div className="skeleton-line title"></div>
    <div className="skeleton-line badge"></div>
    <div className="skeleton-line desc"></div>
    <div className="skeleton-box telemetry"></div>
    <div className="skeleton-box network"></div>
    <div className="skeleton-box footer"></div>
  </div>
);

// SOC Operational Honeypot Card
const HoneypotCard = ({ hp, onSelect }) => {
  const IconComponent = PROTOCOL_ICONS[hp.protocol] || FaServer;
  const isActive = hp.status === "ACTIVE";

  return (
    <div
      className={`honeypot-card ${isActive ? "active" : "inactive"}`}
      onClick={() => onSelect(hp)}
      role="button"
      tabIndex={0}
      aria-label={`Inspect ${hp.title}, Status: ${hp.status}, External Port: ${hp.external_port}, Captured logs: ${hp.packet_count}`}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(hp);
        }
      }}
    >
      <div className="scan-line"></div>
      
      {/* Card Top: Operational Status & Protocol Badge */}
      <div className="card-top-row">
        <div className={`status-pill ${isActive ? "active" : "inactive"}`}>
          <span className="status-dot"></span>
          <span className="status-text hud-font">{hp.status}</span>
        </div>
        <div className="protocol-badge">
          <IconComponent className="proto-icon" />
          <span className="proto-name hud-font">{hp.protocol}</span>
        </div>
      </div>

      {/* Identity */}
      <div className="card-identity">
        <h3 className="card-title">{hp.title}</h3>
        <span className="node-id-pill hud-font">{hp.node_id}</span>
        <p className="card-desc">{hp.description}</p>
      </div>

      {/* Telemetry Strip */}
      <div className="telemetry-strip">
        <div className="telemetry-col">
          <span className="strip-label">CAPTURED EVENTS</span>
          <span className="strip-val value-highlight hud-font">{hp.packet_count}</span>
        </div>
        <div className="telemetry-divider"></div>
        <div className="telemetry-col">
          <span className="strip-label">LAST SEEN</span>
          <span className="strip-val text-dim hud-font">{hp.lastSeenFormatted}</span>
        </div>
      </div>

      {/* Network Ports Distinction (HP-04) */}
      <div className="network-box">
        <div className="network-header">
          <Network size={12} className="net-icon" />
          <span className="hud-font">NETWORK PORTS</span>
        </div>
        <div className="ports-grid">
          <div className="port-item">
            <span className="port-label">EXTERNAL (HOST)</span>
            <span className="port-val host-port hud-font">{hp.external_port}</span>
          </div>
          <div className="port-item">
            <span className="port-label">INTERNAL (CONTAINER)</span>
            <span className="port-val internal-port hud-font">{hp.internal_port}</span>
          </div>
        </div>
      </div>

      {/* Infrastructure Target Container */}
      <div className="target-row">
        <span className="target-label">TARGET:</span>
        <span className="target-val hud-font">{hp.host}</span>
      </div>

      {/* Actions */}
      <button
        type="button"
        className="card-detail-btn"
        aria-label={`View details for ${hp.name} honeypot`}
        onClick={(e) => {
          e.stopPropagation();
          onSelect(hp);
        }}
      >
        <span>View Details</span>
        <ExternalLink size={13} aria-hidden="true" />
      </button>
    </div>
  );
};

const Honeypots = () => {
  const navigate = useNavigate();
  const [honeypots, setHoneypots] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [isAuthError, setIsAuthError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [selectedHoneypot, setSelectedHoneypot] = useState(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // Lifecycle & Request Coordination Refs
  const isMountedRef = useRef(true);
  const isFetchingRef = useRef(false);
  const abortControllerRef = useRef(null);
  const triggerElementRef = useRef(null);
  const modalRef = useRef(null);

  const fetchHoneypotStatus = useCallback(async (isManual = false) => {
    // Prevent overlapping background polling ticks
    if (isFetchingRef.current && !isManual) {
      return;
    }

    if (isManual) {
      setIsRefreshing(true);
    }

    // Abort previous in-flight request if manual refresh requested
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;
    isFetchingRef.current = true;

    try {
      const res = await fetch("/api/honeypots", {
        signal: controller.signal,
        credentials: "include",
        headers: {
          Accept: "application/json",
        },
      });

      if (!isMountedRef.current) return;

      if (res.status === 401) {
        setIsAuthError(true);
        setError("Your session has expired. Please sign in again to access honeypot operations.");
        return;
      }

      if (!res.ok) {
        throw new Error(`API error ${res.status}: Unable to load honeypot telemetry`);
      }

      const data = await res.json();
      if (!isMountedRef.current) return;

      if (Array.isArray(data)) {
        const mapped = data.map((hp) => {
          const proto = (hp.protocol || hp.name || "SSH").toUpperCase();
          const internalPort = hp.internal_port ?? hp.port ?? 0;
          const externalPort = hp.external_port ?? internalPort;
          const statusUpper = (hp.status || "inactive").toUpperCase();

          return {
            id: hp.id || hp.node_id || `hp-${proto.toLowerCase()}`,
            node_id: hp.node_id || `hp-${proto.toLowerCase()}`,
            name: hp.name || proto,
            title: `${hp.name || proto} Honeypot`,
            protocol: proto,
            status: statusUpper,
            internal_port: internalPort,
            external_port: externalPort,
            host: hp.host || "127.0.0.1",
            description: hp.description || "Active deception listening node.",
            last_seen: hp.last_seen || null,
            lastSeenFormatted: formatLastSeen(hp.last_seen),
            packet_count: hp.packet_count ?? hp.total_events ?? 0,
          };
        });

        setHoneypots(mapped);
        setError(null);
        setIsAuthError(false);
        setLastUpdated(new Date().toLocaleTimeString());
      } else {
        throw new Error("Invalid response format received from telemetry API");
      }
    } catch (err) {
      if (err.name === "AbortError") {
        return;
      }
      if (isMountedRef.current) {
        setError(
          err.message || "Honeypot telemetry is temporarily unavailable. Please retry."
        );
      }
    } finally {
      if (abortControllerRef.current === controller) {
        isFetchingRef.current = false;
        abortControllerRef.current = null;
      }
      if (isMountedRef.current) {
        setIsLoading(false);
        if (isManual) {
          setIsRefreshing(false);
        }
      }
    }
  }, []);

  // Exactly one polling loop; cleanly aborted and cancelled on unmount
  useEffect(() => {
    isMountedRef.current = true;
    fetchHoneypotStatus(false);
    const interval = setInterval(() => {
      fetchHoneypotStatus(false);
    }, 5000);

    return () => {
      isMountedRef.current = false;
      clearInterval(interval);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [fetchHoneypotStatus]);

  // Modal open & close handlers with focus restoration
  const handleOpenModal = useCallback((hp) => {
    triggerElementRef.current = document.activeElement;
    setSelectedHoneypot(hp);
  }, []);

  const handleCloseModal = useCallback(() => {
    setSelectedHoneypot(null);
    if (triggerElementRef.current && typeof triggerElementRef.current.focus === "function") {
      triggerElementRef.current.focus();
    }
  }, []);

  // Keyboard escape, focus trap, & body scroll lock for detail modal
  useEffect(() => {
    if (!selectedHoneypot) {
      document.body.style.overflow = "unset";
      return;
    }

    document.body.style.overflow = "hidden";

    // Focus first interactive control in modal
    const focusTimer = setTimeout(() => {
      if (modalRef.current) {
        const focusables = modalRef.current.querySelectorAll(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
        if (focusables.length > 0) {
          focusables[0].focus();
        }
      }
    }, 50);

    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        handleCloseModal();
        return;
      }

      // Trap focus inside modal
      if (e.key === "Tab" && modalRef.current) {
        const focusables = Array.from(
          modalRef.current.querySelectorAll(
            'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
          )
        );
        if (focusables.length === 0) return;

        const first = focusables[0];
        const last = focusables[focusables.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);

    return () => {
      clearTimeout(focusTimer);
      document.body.style.overflow = "unset";
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [selectedHoneypot, handleCloseModal]);

  // Aggregate stats (real backend values)
  const totalHoneypots = honeypots.length;
  const activeCount = useMemo(
    () => honeypots.filter((hp) => hp.status === "ACTIVE").length,
    [honeypots]
  );
  const inactiveCount = useMemo(
    () => honeypots.filter((hp) => hp.status === "INACTIVE").length,
    [honeypots]
  );
  const totalLogs = useMemo(
    () => honeypots.reduce((acc, curr) => acc + (curr.packet_count || 0), 0),
    [honeypots]
  );

  // Filtered honeypots
  const filteredHoneypots = useMemo(() => {
    return honeypots.filter((hp) => {
      // Status filter
      if (statusFilter !== "ALL" && hp.status !== statusFilter) {
        return false;
      }
      // Search query across all operational fields
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const matchesName = hp.name.toLowerCase().includes(query);
        const matchesTitle = hp.title.toLowerCase().includes(query);
        const matchesProto = hp.protocol.toLowerCase().includes(query);
        const matchesExtPort = String(hp.external_port).includes(query);
        const matchesIntPort = String(hp.internal_port).includes(query);
        const matchesNodeId = hp.node_id.toLowerCase().includes(query);
        const matchesHost = hp.host.toLowerCase().includes(query);
        const matchesDesc = hp.description.toLowerCase().includes(query);
        return (
          matchesName ||
          matchesTitle ||
          matchesProto ||
          matchesExtPort ||
          matchesIntPort ||
          matchesNodeId ||
          matchesHost ||
          matchesDesc
        );
      }
      return true;
    });
  }, [honeypots, statusFilter, searchQuery]);

  const showKpiSkeleton = isLoading && honeypots.length === 0 && !error;

  return (
    <div className="honeypots-wrapper">
      {/* ── 1. Page Header ── */}
      <header className="honeypots-header">
        <div className="header-titles">
          <div className="title-row">
            <h1 className="honeypots-title glow-text">Honeypot Network</h1>
            <span className="operational-badge hud-font">
              <span className="badge-pulse-dot"></span>
              DECEPTION MESH
            </span>
          </div>
          <p className="honeypots-subtitle text-dim">
            ACTIVE DEFENSE DECEPTION TOPOLOGY • DISTRIBUTED TELEMETRY
          </p>
        </div>

        {/* Telemetry Status Right */}
        <div className="header-telemetry-badge">
          <div className="telemetry-indicator">
            <Radio size={13} className="live-pulse-icon" aria-hidden="true" />
            <span className="auto-refresh-text hud-font">AUTO-REFRESH: 5S</span>
          </div>
          {lastUpdated && (
            <span className="last-updated-text text-dim hud-font">
              LAST UPDATED: {lastUpdated}
            </span>
          )}
        </div>
      </header>

      {/* ── 2. Operational KPI Strip (Section 8) ── */}
      <section className="honeypots-kpi-strip" aria-label="Operational KPI Summary">
        <div className="kpi-card active">
          <div className="kpi-icon-wrap active">
            <CheckCircle2 size={18} aria-hidden="true" />
          </div>
          <div className="kpi-content">
            <span className="kpi-label">ACTIVE NODES</span>
            {showKpiSkeleton ? (
              <span className="kpi-value kpi-skeleton-val hud-font" aria-label="Loading active nodes count">—</span>
            ) : (
              <span className="kpi-value hud-font text-success">{activeCount}</span>
            )}
          </div>
        </div>

        <div className="kpi-card inactive">
          <div className="kpi-icon-wrap inactive">
            <XCircle size={18} aria-hidden="true" />
          </div>
          <div className="kpi-content">
            <span className="kpi-label">INACTIVE NODES</span>
            {showKpiSkeleton ? (
              <span className="kpi-value kpi-skeleton-val hud-font" aria-label="Loading inactive nodes count">—</span>
            ) : (
              <span className="kpi-value hud-font text-danger">{inactiveCount}</span>
            )}
          </div>
        </div>

        <div className="kpi-card total">
          <div className="kpi-icon-wrap total">
            <Server size={18} aria-hidden="true" />
          </div>
          <div className="kpi-content">
            <span className="kpi-label">TOTAL HONEYPOTS</span>
            {showKpiSkeleton ? (
              <span className="kpi-value kpi-skeleton-val hud-font" aria-label="Loading total honeypots count">—</span>
            ) : (
              <span className="kpi-value hud-font">{totalHoneypots}</span>
            )}
          </div>
        </div>

        <div className="kpi-card events">
          <div className="kpi-icon-wrap events">
            <ShieldCheck size={18} aria-hidden="true" />
          </div>
          <div className="kpi-content">
            <span className="kpi-label">TOTAL CAPTURED EVENTS</span>
            {showKpiSkeleton ? (
              <span className="kpi-value kpi-skeleton-val hud-font" aria-label="Loading total captured events count">—</span>
            ) : (
              <span className="kpi-value hud-font text-highlight">{totalLogs}</span>
            )}
          </div>
        </div>
      </section>

      {/* ── 3. Error Banner (HP-02) ── */}
      {error && (
        <div className="honeypots-error-banner" role="alert">
          <div className="error-left">
            <AlertTriangle className="error-icon" size={20} aria-hidden="true" />
            <div className="error-message">
              <strong>Telemetry Alert:</strong> {error}
            </div>
          </div>
          <div className="error-actions">
            {isAuthError ? (
              <button
                type="button"
                className="error-btn auth"
                onClick={() => navigate("/login")}
              >
                Sign In
              </button>
            ) : (
              <button
                type="button"
                className="error-btn retry"
                onClick={() => fetchHoneypotStatus(true)}
                disabled={isRefreshing}
              >
                <RefreshCw size={13} className={isRefreshing ? "spin" : ""} aria-hidden="true" />
                <span>Retry</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── 4. Operator Control Bar (Search, Status Filter, Refresh) ── */}
      <section className="honeypots-control-bar" aria-label="Operator Controls">
        <div className="control-left">
          {/* Search Box */}
          <div className="search-box">
            <Search size={16} className="search-icon" aria-hidden="true" />
            <input
              type="text"
              className="search-input"
              aria-label="Search honeypots by name, protocol, node ID, or port"
              placeholder="Search by name, protocol, node ID, or port..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button
                type="button"
                className="clear-search-btn"
                onClick={() => setSearchQuery("")}
                aria-label="Clear search query"
              >
                <X size={14} aria-hidden="true" />
              </button>
            )}
          </div>

          {/* Status Filter */}
          <div className="filter-group">
            <SlidersHorizontal size={14} className="filter-icon" aria-hidden="true" />
            <select
              className="filter-select"
              aria-label="Filter honeypots by operational status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="ALL">All Statuses</option>
              <option value="ACTIVE">Active Only</option>
              <option value="INACTIVE">Inactive Only</option>
            </select>
          </div>

          {/* Result Count Indicator */}
          {!isLoading && (
            <span className="match-counter hud-font text-dim">
              Showing {filteredHoneypots.length} of {totalHoneypots} nodes
            </span>
          )}
        </div>

        <div className="control-right">
          {/* Manual Refresh Button */}
          <button
            type="button"
            className="refresh-btn"
            onClick={() => fetchHoneypotStatus(true)}
            disabled={isRefreshing}
            aria-label="Manually refresh honeypot telemetry"
            title="Refresh honeypot telemetry immediately"
          >
            <RefreshCw size={14} className={isRefreshing ? "spin" : ""} aria-hidden="true" />
            <span>{isRefreshing ? "Refreshing..." : "Refresh"}</span>
          </button>
        </div>
      </section>

      {/* ── 5. Main Content: Skeleton, Grid, or Empty State ── */}
      {isLoading && honeypots.length === 0 && !error ? (
        <div className="honeypots-grid skeleton-grid" aria-label="Loading honeypots">
          {[1, 2, 3, 4].map((i) => (
            <HoneypotCardSkeleton key={i} />
          ))}
        </div>
      ) : honeypots.length === 0 && !error ? (
        /* State E: Empty Database State */
        <section className="honeypots-empty-state empty-db" aria-label="No honeypots configured">
          <div className="empty-icon-wrap">
            <Server size={32} aria-hidden="true" />
          </div>
          <h3>No Honeypot Nodes Registered</h3>
          <p>
            The deception network topology is currently empty. No honeypot containers are registered in the database.
          </p>
          <button
            type="button"
            className="empty-reset-btn"
            onClick={() => fetchHoneypotStatus(true)}
            disabled={isRefreshing}
          >
            {isRefreshing ? "Refreshing..." : "Refresh Telemetry"}
          </button>
        </section>
      ) : filteredHoneypots.length > 0 ? (
        /* State B: Success Grid */
        <main className="honeypots-grid" aria-label="Active Honeypot Nodes">
          {filteredHoneypots.map((hp) => (
            <HoneypotCard
              key={hp.id}
              hp={hp}
              onSelect={handleOpenModal}
            />
          ))}
        </main>
      ) : (
        /* State F: Filter Empty State */
        <section className="honeypots-empty-state" aria-label="No results">
          <div className="empty-icon-wrap">
            <Search size={32} aria-hidden="true" />
          </div>
          <h3>No honeypots match the current filters.</h3>
          <p>
            No active or inactive nodes match &ldquo;{searchQuery}&rdquo; with status &ldquo;{statusFilter}&rdquo;.
          </p>
          <button
            type="button"
            className="empty-reset-btn"
            onClick={() => {
              setSearchQuery("");
              setStatusFilter("ALL");
            }}
          >
            Reset Filters
          </button>
        </section>
      )}

      {/* ── 6. Detail Modal / Inspection Panel (Section 18) ── */}
      {selectedHoneypot && (
        <div
          className="honeypot-modal-overlay"
          onClick={handleCloseModal}
          role="presentation"
        >
          <div
            ref={modalRef}
            className="honeypot-modal"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="modal-honeypot-title"
            aria-describedby="modal-honeypot-desc"
          >
            {/* Modal Header */}
            <div className="modal-header">
              <div className="modal-title-wrap">
                <div className="modal-icon-box">
                  {React.createElement(
                    PROTOCOL_ICONS[selectedHoneypot.protocol] || FaServer
                  )}
                </div>
                <div>
                  <h2 id="modal-honeypot-title" className="modal-title">
                    {selectedHoneypot.title}
                  </h2>
                  <span className="modal-subtitle hud-font text-dim">
                    NODE ID: {selectedHoneypot.node_id}
                  </span>
                </div>
              </div>
              <div className="modal-header-actions">
                <span
                  className={`modal-status-badge ${selectedHoneypot.status.toLowerCase()}`}
                >
                  <span className="status-dot"></span>
                  {selectedHoneypot.status}
                </span>
                <button
                  type="button"
                  className="modal-close-btn"
                  onClick={handleCloseModal}
                  aria-label="Close honeypot details"
                  title="Close inspection dialog"
                >
                  <X size={18} aria-hidden="true" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="modal-body">
              {/* Description Callout */}
              <div className="modal-desc-box">
                <Activity size={16} className="desc-icon" aria-hidden="true" />
                <p id="modal-honeypot-desc" className="modal-desc">{selectedHoneypot.description}</p>
              </div>

              {/* Organized Sections */}
              <div className="modal-section">
                <h4 className="section-title hud-font">IDENTITY & PROTOCOL</h4>
                <div className="modal-details-grid">
                  <div className="detail-item">
                    <span className="detail-label">Node Identifier</span>
                    <span className="detail-val hud-font text-highlight">
                      {selectedHoneypot.node_id}
                    </span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Service Protocol</span>
                    <span className="detail-val hud-font">
                      {selectedHoneypot.protocol}
                    </span>
                  </div>
                </div>
              </div>

              <div className="modal-section">
                <h4 className="section-title hud-font">NETWORK ARCHITECTURE (HP-04)</h4>
                <div className="modal-details-grid">
                  <div className="detail-item">
                    <span className="detail-label">External (Host) Port</span>
                    <span className="detail-val host-port hud-font">
                      {selectedHoneypot.external_port}
                    </span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Internal (Container) Port</span>
                    <span className="detail-val internal-port hud-font">
                      {selectedHoneypot.internal_port}
                    </span>
                  </div>
                </div>
              </div>

              <div className="modal-section">
                <h4 className="section-title hud-font">INFRASTRUCTURE TARGET</h4>
                <div className="modal-details-grid">
                  <div className="detail-item">
                    <span className="detail-label">Container Target</span>
                    <span className="detail-val hud-font">
                      {selectedHoneypot.host}
                    </span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Operational Status</span>
                    <span
                      className={`detail-val hud-font ${
                        selectedHoneypot.status === "ACTIVE"
                          ? "text-success"
                          : "text-danger"
                      }`}
                    >
                      {selectedHoneypot.status === "ACTIVE"
                        ? "ACTIVE (Socket Verified)"
                        : `${selectedHoneypot.status} (Offline / Unreachable)`}
                    </span>
                  </div>
                </div>
              </div>

              <div className="modal-section">
                <h4 className="section-title hud-font">TELEMETRY & LOG ACTIVITY</h4>
                <div className="modal-details-grid">
                  <div className="detail-item">
                    <span className="detail-label">Captured Logs</span>
                    <span className="detail-val value-highlight hud-font">
                      {selectedHoneypot.packet_count} events
                    </span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Last Activity Timestamp</span>
                    <span className="detail-val hud-font text-dim">
                      {selectedHoneypot.last_seen || "No activity recorded yet"}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="modal-footer">
              <button
                type="button"
                className="modal-action-btn secondary"
                onClick={handleCloseModal}
              >
                Close
              </button>
              <button
                type="button"
                className="modal-action-btn primary"
                onClick={() => {
                  setSelectedHoneypot(null);
                  navigate(`/events?protocol=${selectedHoneypot.protocol}`);
                }}
              >
                <span>Inspect Protocol Events</span>
                <ExternalLink size={14} aria-hidden="true" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Honeypots;