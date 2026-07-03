import React, { useState, useCallback, useEffect, useRef, useMemo } from "react";
import {
  FaBook,
  FaTimes,
  FaShieldAlt,
  FaFileCode,
  FaMarkdown,
  FaCrosshairs,
  FaCalendarAlt,
  FaCheckCircle,
  FaRegCircle,
  FaExclamationTriangle,
  FaInfoCircle,
  FaClipboardCheck,
  FaDownload,
  FaExpand,
  FaCompress,
  FaFileAlt,
  FaCubes,
} from "react-icons/fa";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import RulePreview from "./RulePreview";
import ApprovalControls from "./ApprovalControls";
import LoadingSpinner from "../LoadingSpinner";
import "../../Styles/components/PlaybookViewer.css";

/* ═══════════════════════════════════════════════════════════════
   Tab Configuration
   ═══════════════════════════════════════════════════════════════ */

const TABS = [
  { key: "playbook", label: "Playbook",    icon: FaBook },
  { key: "snort",    label: "Snort Rules",  icon: FaShieldAlt },
  { key: "sigma",    label: "Sigma Rules",  icon: FaFileCode },
];

/* ═══════════════════════════════════════════════════════════════
   Severity Helpers
   ═══════════════════════════════════════════════════════════════ */

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high:     "#f59e0b",
  medium:   "#3b82f6",
  low:      "#22c55e",
};

const SEVERITY_ICONS = {
  critical: "🔴",
  high:     "🟠",
  medium:   "🟡",
  low:      "🟢",
};

/* ═══════════════════════════════════════════════════════════════
   Checkbox Tracker — stateful wrapper for containment checkboxes
   ═══════════════════════════════════════════════════════════════ */

/**
 * useCheckboxTracker
 * Manages the checked state of all `- [ ]` and `- [x]` checkboxes
 * found in the markdown content, keyed by their position index.
 */
const useCheckboxTracker = (markdownContent) => {
  const [checkedItems, setCheckedItems] = useState({});

  const toggleCheckbox = useCallback((index) => {
    setCheckedItems((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  }, []);

  const totalCheckboxes = useMemo(() => {
    if (!markdownContent) return 0;
    return (markdownContent.match(/- \[[ x]\]/gi) || []).length;
  }, [markdownContent]);

  const completedCount = useMemo(() => {
    return Object.values(checkedItems).filter(Boolean).length;
  }, [checkedItems]);

  return { checkedItems, toggleCheckbox, totalCheckboxes, completedCount };
};

/* ═══════════════════════════════════════════════════════════════
   Custom Markdown Components — react-markdown overrides
   ═══════════════════════════════════════════════════════════════ */

/**
 * Detects if a table is an IOC table by checking header text.
 * IOC tables typically have columns like IP, Port, Protocol, etc.
 */
const isIOCTable = (children) => {
  if (!children || !children[0]) return false;
  const firstRow = children[0];
  if (!firstRow?.props?.children) return false;
  const headerText = String(
    React.Children.toArray(firstRow.props.children)
      .map((c) => (typeof c === "string" ? c : c?.props?.children || ""))
      .join(" ")
  ).toLowerCase();
  return (
    headerText.includes("ip") ||
    headerText.includes("port") ||
    headerText.includes("protocol") ||
    headerText.includes("ioc") ||
    headerText.includes("hash") ||
    headerText.includes("domain") ||
    headerText.includes("indicator")
  );
};

/**
 * Detects if a table is a metadata/info table (header-like key-value).
 */
const isMetadataTable = (children) => {
  if (!children || !children[0]) return false;
  const firstRow = children[0];
  if (!firstRow?.props?.children) return false;
  const headerText = String(
    React.Children.toArray(firstRow.props.children)
      .map((c) => (typeof c === "string" ? c : c?.props?.children || ""))
      .join(" ")
  ).toLowerCase();
  return (
    headerText.includes("field") ||
    headerText.includes("property") ||
    headerText.includes("metric") ||
    headerText.includes("role") ||
    headerText.includes("dimension") ||
    headerText.includes("rule id") ||
    headerText.includes("source") ||
    headerText.includes("sla")
  );
};

/**
 * Creates the set of custom react-markdown component overrides.
 */
const createMarkdownComponents = (checkedItems, toggleCheckbox, checkboxOffsets) => ({
  /* ── Tables ── */
  table: ({ children, ...props }) => {
    const tableType = isIOCTable(children)
      ? "ioc-table"
      : isMetadataTable(children)
      ? "metadata-table"
      : "default-table";
    return (
      <div className={`pbv-table-wrapper ${tableType}`}>
        <div className="pbv-table-scroll">
          <table {...props}>{children}</table>
        </div>
      </div>
    );
  },

  thead: ({ children, ...props }) => (
    <thead className="pbv-thead" {...props}>
      {children}
    </thead>
  ),

  th: ({ children, ...props }) => (
    <th className="pbv-th" {...props}>
      {children}
    </th>
  ),

  td: ({ children, ...props }) => {
    const text = String(children || "");
    // Add special styling for severity-like values
    const isSeverityValue =
      /^(critical|high|medium|low)$/i.test(text.trim()) ||
      /^🔴|🟠|🟡|🟢/.test(text.trim());
    const isStatus = /^(✅|❌|⚠️|❓|ℹ️)/.test(text.trim());
    return (
      <td
        className={`pbv-td ${isSeverityValue ? "severity-cell" : ""} ${
          isStatus ? "status-cell" : ""
        }`}
        {...props}
      >
        {children}
      </td>
    );
  },

  /* ── Headings with section anchors ── */
  h1: ({ children, ...props }) => (
    <h1 className="pbv-heading pbv-h1" {...props}>
      {children}
    </h1>
  ),
  h2: ({ children, ...props }) => {
    const text = String(children || "");
    const isContainment =
      text.toLowerCase().includes("containment") ||
      text.toLowerCase().includes("response");
    const isIOC =
      text.toLowerCase().includes("ioc") ||
      text.toLowerCase().includes("indicator");
    return (
      <h2
        className={`pbv-heading pbv-h2 ${
          isContainment ? "containment-heading" : ""
        } ${isIOC ? "ioc-heading" : ""}`}
        {...props}
      >
        {children}
        {isContainment && (
          <span className="heading-badge containment-badge">
            <FaClipboardCheck /> Response
          </span>
        )}
        {isIOC && (
          <span className="heading-badge ioc-badge">
            <FaCrosshairs /> IOCs
          </span>
        )}
      </h2>
    );
  },
  h3: ({ children, ...props }) => (
    <h3 className="pbv-heading pbv-h3" {...props}>
      {children}
    </h3>
  ),
  h4: ({ children, ...props }) => (
    <h4 className="pbv-heading pbv-h4" {...props}>
      {children}
    </h4>
  ),

  /* ── Blockquotes with alert detection ── */
  blockquote: ({ children, ...props }) => {
    const text = String(
      React.Children.toArray(children)
        .map((c) => (typeof c === "string" ? c : c?.props?.children || ""))
        .join(" ")
    );
    const isWarning =
      text.includes("⚠️") ||
      text.includes("WARNING") ||
      text.includes("CRITICAL") ||
      text.includes("⚡");
    const isInfo = text.includes("ℹ️") || text.includes("📖");
    return (
      <blockquote
        className={`pbv-blockquote ${isWarning ? "blockquote-warning" : ""} ${
          isInfo ? "blockquote-info" : ""
        }`}
        {...props}
      >
        {isWarning && (
          <FaExclamationTriangle className="blockquote-icon warning-icon" />
        )}
        {isInfo && <FaInfoCircle className="blockquote-icon info-icon" />}
        {children}
      </blockquote>
    );
  },

  /* ── Code blocks ── */
  code: ({ className, children, ...props }) => {
    const isBlock = className?.includes("language-");
    const language = className?.replace("language-", "") || "";
    if (isBlock) {
      return (
        <div className="pbv-code-block-wrapper">
          <div className="pbv-code-lang-label">{language.toUpperCase()}</div>
          <code className={`pbv-code-block ${className}`} {...props}>
            {children}
          </code>
        </div>
      );
    }
    return (
      <code className="pbv-inline-code" {...props}>
        {children}
      </code>
    );
  },

  /* ── Links ── */
  a: ({ children, href, ...props }) => (
    <a
      className="pbv-link"
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      {...props}
    >
      {children}
      <span className="link-external-icon">↗</span>
    </a>
  ),

  /* ── List items with interactive checkboxes ── */
  li: ({ node, children, ...props }) => {
    // Detect GFM task list items
    const childArray = React.Children.toArray(children);
    const firstChild = childArray[0];

    // Check if this is a task-list item (contains an input checkbox from remark-gfm)
    let isTaskItem = false;
    let isDefaultChecked = false;

    if (
      firstChild &&
      typeof firstChild === "object" &&
      firstChild.type === "input" &&
      firstChild.props?.type === "checkbox"
    ) {
      isTaskItem = true;
      isDefaultChecked = firstChild.props?.checked || false;
    }

    if (isTaskItem) {
      const startOffset = node?.position?.start?.offset;
      let idx = -1;
      if (startOffset !== undefined) {
        idx = checkboxOffsets.findIndex(
          (offset) => Math.abs(offset - startOffset) < 10
        );
      }

      if (idx !== -1) {
        const isChecked =
          checkedItems[idx] !== undefined ? checkedItems[idx] : isDefaultChecked;

        return (
          <li
            className={`pbv-task-item ${isChecked ? "task-completed" : "task-pending"}`}
            {...props}
          >
            <button
              className={`pbv-checkbox-btn ${isChecked ? "checked" : ""}`}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                toggleCheckbox(idx);
              }}
              aria-label={isChecked ? "Mark as incomplete" : "Mark as complete"}
              type="button"
            >
              {isChecked ? (
                <FaCheckCircle className="checkbox-icon checked-icon" />
              ) : (
                <FaRegCircle className="checkbox-icon unchecked-icon" />
              )}
            </button>
            <span className={`task-text ${isChecked ? "text-completed" : ""}`}>
              {childArray.slice(1)}
            </span>
            {isChecked && <span className="task-check-anim" />}
          </li>
        );
      }
    }

    return <li className="pbv-list-item" {...props}>{children}</li>;
  },

  /* ── Horizontal rules ── */
  hr: () => <hr className="pbv-divider" />,

  /* ── Paragraphs ── */
  p: ({ children, ...props }) => (
    <p className="pbv-paragraph" {...props}>
      {children}
    </p>
  ),

  /* ── Strong / emphasis ── */
  strong: ({ children, ...props }) => (
    <strong className="pbv-strong" {...props}>
      {children}
    </strong>
  ),

  /* ── Images ── */
  img: ({ alt, src, ...props }) => (
    <div className="pbv-image-wrapper">
      <img className="pbv-image" alt={alt} src={src} loading="lazy" {...props} />
      {alt && <span className="pbv-image-caption">{alt}</span>}
    </div>
  ),
});

/* ═══════════════════════════════════════════════════════════════
   MarkdownRenderer — Full-featured markdown rendering
   ═══════════════════════════════════════════════════════════════ */

const MarkdownRenderer = ({ content }) => {
  const { checkedItems, toggleCheckbox, totalCheckboxes, completedCount } =
    useCheckboxTracker(content);

  // Pre-calculate checkbox offsets to avoid accessing refs during render
  const checkboxOffsets = useMemo(() => {
    if (!content) return [];
    const offsets = [];
    const regex = /- \[[ x]\]/gi;
    let match;
    while ((match = regex.exec(content)) !== null) {
      offsets.push(match.index);
    }
    return offsets;
  }, [content]);

  const components = useMemo(
    () => createMarkdownComponents(checkedItems, toggleCheckbox, checkboxOffsets),
    [checkedItems, toggleCheckbox, checkboxOffsets]
  );

  if (!content) {
    return (
      <div className="pbv-markdown-placeholder">
        <FaMarkdown className="pbv-placeholder-icon" />
        <h3 className="pbv-placeholder-title">
          No Playbook Content
        </h3>
        <p className="pbv-placeholder-text">
          Select a playbook or verify that the markdown content is defined.
        </p>
      </div>
    );
  }

  const progressPercent =
    totalCheckboxes > 0
      ? Math.round((completedCount / totalCheckboxes) * 100)
      : 0;

  return (
    <div className="pbv-markdown-content">
      {/* Containment Progress Tracker */}
      {totalCheckboxes > 0 && (
        <div className="pbv-containment-progress">
          <div className="progress-header">
            <div className="progress-label">
              <FaClipboardCheck className="progress-icon" />
              <span>Containment Progress</span>
            </div>
            <div className="progress-stats">
              <span className="progress-count">
                {completedCount}/{totalCheckboxes}
              </span>
              <span className="progress-percentage">{progressPercent}%</span>
            </div>
          </div>
          <div className="progress-bar-track">
            <div
              className={`progress-bar-fill ${
                progressPercent === 100 ? "complete" : ""
              }`}
              style={{ width: `${progressPercent}%` }}
            />
          </div>
          {progressPercent === 100 && (
            <div className="progress-complete-msg">
              <FaCheckCircle /> All containment steps completed
            </div>
          )}
        </div>
      )}

      {/* Rendered Markdown */}
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </ReactMarkdown>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════════════
   PlaybookViewer Component
   ─────────────────────────────────────────────────────────────
   Modal / panel that renders a full security playbook with
   three tabbed views: Playbook content, Snort rules, Sigma rules.

   Props:
   ────────────────────────────────────────────────────────────
   @param {boolean}  isOpen         – Whether the modal is visible
   @param {function} onClose        – Callback to close the modal
   @param {string}   title          – Playbook title
   @param {string}   severity       – "critical" | "high" | "medium" | "low"
   @param {string}   technique      – MITRE ATT&CK technique ID
   @param {string}   date           – Human-readable date string
   @param {string}   markdownContent– Raw Markdown string for the playbook body
   @param {string}   snortRule      – Raw Snort rule text
   @param {string}   sigmaRule      – Raw Sigma YAML text
   ═══════════════════════════════════════════════════════════════ */

const PlaybookViewer = ({
  isOpen = false,
  onClose,
  id,
  status = "pending",
  onStatusChange,
  title = "Untitled Playbook",
  severity = "medium",
  technique = "T0000",
  date = "—",
  markdownContent = "",
  playbook_content = "",
  snortRule = "",
  sigmaRule = "",
  isLoading = false,
}) => {
  const [activeTab, setActiveTab] = useState("playbook");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const panelRef = useRef(null);

  const resolvedMarkdown = playbook_content || markdownContent;

  /* ── Close on Escape ── */
  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e) => {
      if (e.key === "Escape") {
        if (isFullscreen) {
          setIsFullscreen(false);
        } else {
          onClose?.();
        }
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose, isFullscreen]);

  /* ── Lock body scroll when open ── */
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [isOpen]);

  /* ── Close on overlay click ── */
  const handleOverlayClick = useCallback(
    (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        onClose?.();
      }
    },
    [onClose]
  );

  // Modal state is reset via parent key unmount/remount

  /* ── Download helper ── */
  const triggerDownload = useCallback((content, filename, mimeType = "text/plain;charset=utf-8") => {
    if (!content) return;
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, []);

  const safeTitle = title.replace(/\s+/g, "_");

  /* ── Export current tab (header button) ── */
  const handleExport = useCallback(() => {
    const content = activeTab === "playbook" ? resolvedMarkdown : activeTab === "snort" ? snortRule : sigmaRule;
    const ext = activeTab === "playbook" ? "md" : activeTab === "snort" ? "rules" : "yml";
    triggerDownload(content, `${safeTitle}.${ext}`);
  }, [activeTab, resolvedMarkdown, snortRule, sigmaRule, safeTitle, triggerDownload]);

  /* ── Format-specific downloads ── */
  const handleDownloadSnort = useCallback(() => {
    triggerDownload(snortRule, `${safeTitle}_snort.rules`);
  }, [snortRule, safeTitle, triggerDownload]);

  const handleDownloadSigma = useCallback(() => {
    triggerDownload(sigmaRule, `${safeTitle}_sigma.yml`);
  }, [sigmaRule, safeTitle, triggerDownload]);

  const handleDownloadSTIX = useCallback(() => {
    const stixBundle = JSON.stringify({
      type: "bundle",
      id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : Date.now()}`,
      spec_version: "2.1",
      created: new Date().toISOString(),
      objects: [
        {
          type: "attack-pattern",
          id: `attack-pattern--${technique}`,
          name: title,
          description: `Sentinel playbook for technique ${technique}`,
          external_references: [
            {
              source_name: "mitre-attack",
              external_id: technique,
              url: `https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`,
            },
          ],
        },
        {
          type: "indicator",
          id: `indicator--${Date.now()}`,
          name: `${title} - Detection Indicator`,
          pattern_type: "snort",
          pattern: snortRule || "[no snort rule]",
          valid_from: new Date().toISOString(),
          labels: ["malicious-activity"],
        },
        {
          type: "note",
          id: `note--${Date.now() + 1}`,
          content: resolvedMarkdown || "No playbook content",
          object_refs: [`attack-pattern--${technique}`],
        },
      ],
    }, null, 2);
    triggerDownload(stixBundle, `${safeTitle}_stix.json`, "application/json;charset=utf-8");
  }, [technique, title, snortRule, resolvedMarkdown, safeTitle, triggerDownload]);

  const handleDownloadPlaybook = useCallback(() => {
    triggerDownload(resolvedMarkdown, `${safeTitle}_playbook.md`);
  }, [resolvedMarkdown, safeTitle, triggerDownload]);

  /* ── Download buttons config ── */
  const downloadButtons = [
    { label: "Snort Rules",  ext: ".rules", icon: FaShieldAlt, handler: handleDownloadSnort,    disabled: !snortRule },
    { label: "Sigma Rules",  ext: ".yml",   icon: FaFileCode,  handler: handleDownloadSigma,    disabled: !sigmaRule },
    { label: "STIX Bundle",  ext: ".json",  icon: FaCubes,     handler: handleDownloadSTIX,     disabled: !resolvedMarkdown && !snortRule },
    { label: "Playbook",     ext: ".md",    icon: FaFileAlt,   handler: handleDownloadPlaybook, disabled: !resolvedMarkdown },
  ];

  if (!isOpen) return null;

  const severityColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium;
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);

  /* ── Determine which tabs are available ── */
  const availableTabs = TABS.filter((tab) => {
    if (tab.key === "snort" && !snortRule) return false;
    if (tab.key === "sigma" && !sigmaRule) return false;
    return true;
  });

  /* ── Determine markdown readiness status ── */
  const hasMarkdown = Boolean(resolvedMarkdown);

  return (
    <div
      className="playbook-viewer-overlay"
      onClick={handleOverlayClick}
      role="dialog"
      aria-modal="true"
      aria-label={`Playbook Viewer: ${title}`}
      id="playbook-viewer-overlay"
    >
      <div
        className={`playbook-viewer-panel ${isFullscreen ? "fullscreen" : ""}`}
        ref={panelRef}
      >
        {/* HUD Corners */}
        <div className="hud-corner top-left"></div>
        <div className="hud-corner top-right"></div>
        <div className="hud-corner bottom-left"></div>
        <div className="hud-corner bottom-right"></div>
        <div className="playbook-viewer-scan-line"></div>
        <div className="playbook-viewer-glow"></div>

        {/* ═══ Header ═══ */}
        <header className="pbv-header">
          <div className="pbv-header-left">
            <div className="pbv-header-icon">
              <FaBook />
            </div>
            <div className="pbv-header-info">
              <h2 className="pbv-title" title={title}>
                {title}
              </h2>
              <div className="pbv-subtitle">
                <span
                  className="severity-dot-inline"
                  style={{
                    background: severityColor,
                    boxShadow: `0 0 6px ${severityColor}`,
                  }}
                ></span>
                <span>{severityLabel}</span>
                <span style={{ opacity: 0.35 }}>│</span>
                <FaCrosshairs style={{ fontSize: "0.55rem", opacity: 0.6 }} />
                <span>{technique}</span>
                <span style={{ opacity: 0.35 }}>│</span>
                <FaCalendarAlt style={{ fontSize: "0.55rem", opacity: 0.6 }} />
                <span>{date}</span>
              </div>
            </div>
          </div>

          <div className="pbv-header-actions">
            <button
              className="pbv-action-btn"
              onClick={handleExport}
              title="Export content"
              aria-label="Export playbook"
              id="playbook-viewer-export-btn"
            >
              <FaDownload />
            </button>
            <button
              className="pbv-action-btn"
              onClick={() => setIsFullscreen((f) => !f)}
              title={isFullscreen ? "Exit fullscreen" : "Enter fullscreen"}
              aria-label={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
              id="playbook-viewer-fullscreen-btn"
            >
              {isFullscreen ? <FaCompress /> : <FaExpand />}
            </button>
            <button
              className="pbv-close-btn"
              onClick={onClose}
              title="Close viewer (Esc)"
              aria-label="Close playbook viewer"
              id="playbook-viewer-close-btn"
            >
              <FaTimes />
            </button>
          </div>
        </header>

        {/* ═══ Tab Bar ═══ */}
        <nav className="pbv-tab-bar" role="tablist" aria-label="Playbook sections">
          {availableTabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                className={`pbv-tab ${activeTab === tab.key ? "active" : ""}`}
                onClick={() => setActiveTab(tab.key)}
                role="tab"
                aria-selected={activeTab === tab.key}
                aria-controls={`pbv-panel-${tab.key}`}
                id={`pbv-tab-${tab.key}`}
              >
                <span className="tab-indicator"></span>
                <Icon className="pbv-tab-icon" />
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* ═══ Download Bar ═══ */}
        {!isLoading && (
          <div className="pbv-download-bar">
            {downloadButtons.map((btn) => {
              const BtnIcon = btn.icon;
              return (
                <button
                  key={btn.label}
                  className="pbv-download-btn"
                  onClick={btn.handler}
                  disabled={btn.disabled}
                  title={btn.disabled ? `No ${btn.label} available` : `Download ${btn.label} (${btn.ext})`}
                >
                  <BtnIcon className="pbv-download-btn-icon" />
                  <span className="pbv-download-btn-label">{btn.label}</span>
                  <span className="pbv-download-btn-ext">{btn.ext}</span>
                </button>
              );
            })}
          </div>
        )}

        {/* ═══ Content Area ═══ */}
        <div className="pbv-content-area">
          {isLoading ? (
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "250px", flexDirection: "column" }}>
              <LoadingSpinner />
            </div>
          ) : (
            <>
              {/* ── Playbook Tab ── */}
              {activeTab === "playbook" && (
                <div
                  role="tabpanel"
                  id="pbv-panel-playbook"
                  aria-labelledby="pbv-tab-playbook"
                >
                  <MarkdownRenderer key={resolvedMarkdown} content={resolvedMarkdown} />
                </div>
              )}

              {/* ── Snort Rules Tab ── */}
              {activeTab === "snort" && (
                <div
                  className="pbv-rule-section"
                  role="tabpanel"
                  id="pbv-panel-snort"
                  aria-labelledby="pbv-tab-snort"
                >
                  <RulePreview snortRule={snortRule} sigmaRule="" />
                </div>
              )}

              {/* ── Sigma Rules Tab ── */}
              {activeTab === "sigma" && (
                <div
                  className="pbv-rule-section"
                  role="tabpanel"
                  id="pbv-panel-sigma"
                  aria-labelledby="pbv-tab-sigma"
                >
                  <RulePreview snortRule="" sigmaRule={sigmaRule} />
                </div>
              )}
            </>
          )}
        </div>

        {/* ═══ Approval Controls ═══ */}
        {id && (
          <ApprovalControls
            playbookId={id}
            status={status}
            onStatusChange={onStatusChange}
          />
        )}

        {/* ═══ Footer ═══ */}
        <footer className="pbv-footer">
          <div className="pbv-footer-left">
            <span className="pbv-footer-label">PhantomNet Sentinel</span>
            <span className="pbv-footer-label" style={{ opacity: 0.4 }}>
              │
            </span>
            <span className="pbv-footer-label">
              {activeTab === "playbook"
                ? "Playbook Content"
                : activeTab === "snort"
                ? "Snort IDS Rule"
                : "Sigma Detection Rule"}
            </span>
          </div>
          <div className="pbv-footer-right">
            <span
              className={`pbv-footer-status ${
                hasMarkdown ? "status-ready" : "status-pending"
              }`}
            >
              <span className="footer-status-dot"></span>
              {hasMarkdown ? "Loaded" : "Awaiting Data"}
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default PlaybookViewer;
