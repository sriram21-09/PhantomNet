import React, { useState, useEffect, useCallback } from "react";
import PropTypes from "prop-types";
import {
  FaTimes,
  FaExchangeAlt,
  FaShieldAlt,
  FaFileCode,
  FaCheckCircle,
  FaExclamationTriangle,
  FaInfoCircle,
  FaSpinner,
  FaCheck,
  FaBan,
  FaBug,
  FaLayerGroup,
  FaDownload,
} from "react-icons/fa";
import "../../Styles/components/PlaybookCompareModal.css";

/**
 * Line-by-line diff calculator for Snort / Sigma rule texts
 */
const computeTextDiff = (text1 = "", text2 = "") => {
  const lines1 = text1.split("\n");
  const lines2 = text2.split("\n");
  const maxLen = Math.max(lines1.length, lines2.length);
  const result = [];

  for (let i = 0; i < maxLen; i++) {
    const l1 = lines1[i] !== undefined ? lines1[i] : null;
    const l2 = lines2[i] !== undefined ? lines2[i] : null;

    if (l1 === l2) {
      result.push({ type: "same", line1: l1, line2: l2, num1: i + 1, num2: i + 1 });
    } else {
      if (l1 !== null) {
        result.push({ type: "del", line1: l1, line2: null, num1: i + 1, num2: null });
      }
      if (l2 !== null) {
        result.push({ type: "add", line1: null, line2: l2, num1: null, num2: i + 1 });
      }
    }
  }
  return result;
};

/**
 * PlaybookCompareModal Component
 * Side-by-side comparison modal for 2 Sentinel security playbooks with diff highlights.
 */
export default function PlaybookCompareModal({
  isOpen,
  onClose,
  id1,
  id2,
  playbook1: initialPb1 = null,
  playbook2: initialPb2 = null,
  onApprove,
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [comparisonData, setComparisonData] = useState(null);
  const [activeTab, setActiveTab] = useState("overview"); // "overview" | "snort" | "sigma" | "cve"

  const fetchComparison = useCallback(async () => {
    if (!id1 || !id2) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/sentinel/playbooks/compare?id1=${id1}&id2=${id2}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch comparison: HTTP ${response.status}`);
      }
      const data = await response.json();
      if (data.status === "success" && data.comparison) {
        setComparisonData(data.comparison);
      } else {
        throw new Error(data.detail || "Invalid comparison data structure");
      }
    } catch (err) {
      console.warn("API comparison fetch failed, computing client-side fallback diff:", err);
      if (initialPb1 && initialPb2) {
        setComparisonData({
          playbook_1: initialPb1,
          playbook_2: initialPb2,
          cve_1: [],
          cve_2: [],
          diff_summary: {
            attack_type_match: initialPb1.attack_type === initialPb2.attack_type,
            technique_match: initialPb1.technique_id === initialPb2.technique_id,
            severity_match: initialPb1.severity === initialPb2.severity,
            confidence_diff: Math.abs((initialPb1.confidence_score || 0.9) - (initialPb2.confidence_score || 0.9)),
            snort_rules_identical: (initialPb1.snort_rule || "") === (initialPb2.snort_rule || ""),
            sigma_rules_identical: (initialPb1.sigma_rule || "") === (initialPb2.sigma_rule || ""),
            ioc_count_1: initialPb1.src_ip ? 1 : 0,
            ioc_count_2: initialPb2.src_ip ? 1 : 0,
            ioc_count_diff: Math.abs((initialPb1.src_ip ? 1 : 0) - (initialPb2.src_ip ? 1 : 0)),
          },
        });
      } else {
        setError(err.message || "Failed to load playbook comparison");
      }
    } finally {
      setLoading(false);
    }
  }, [id1, id2, initialPb1, initialPb2]);

  useEffect(() => {
    if (isOpen) {
      if (id1 && id2) {
        fetchComparison();
      } else if (initialPb1 && initialPb2) {
        setComparisonData({
          playbook_1: initialPb1,
          playbook_2: initialPb2,
          cve_1: [],
          cve_2: [],
          diff_summary: {
            attack_type_match: initialPb1.attack_type === initialPb2.attack_type,
            technique_match: initialPb1.technique_id === initialPb2.technique_id,
            severity_match: initialPb1.severity === initialPb2.severity,
            confidence_diff: Math.abs((initialPb1.confidence_score || 0.9) - (initialPb2.confidence_score || 0.9)),
            snort_rules_identical: (initialPb1.snort_rule || "") === (initialPb2.snort_rule || ""),
            sigma_rules_identical: (initialPb1.sigma_rule || "") === (initialPb2.sigma_rule || ""),
            ioc_count_1: initialPb1.src_ip ? 1 : 0,
            ioc_count_2: initialPb2.src_ip ? 1 : 0,
            ioc_count_diff: Math.abs((initialPb1.src_ip ? 1 : 0) - (initialPb2.src_ip ? 1 : 0)),
          },
        });
      }
    }
  }, [isOpen, id1, id2, initialPb1, initialPb2, fetchComparison]);

  if (!isOpen) return null;

  const pb1 = comparisonData?.playbook_1 || initialPb1 || {};
  const pb2 = comparisonData?.playbook_2 || initialPb2 || {};
  const diff = comparisonData?.diff_summary || {};
  const cve1 = comparisonData?.cve_1 || [];
  const cve2 = comparisonData?.cve_2 || [];

  const snortDiff = computeTextDiff(pb1.snort_rule || "", pb2.snort_rule || "");
  const sigmaDiff = computeTextDiff(pb1.sigma_rule || "", pb2.sigma_rule || "");

  return (
    <div className="pcm-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="compare-modal-title">
      <div className="pcm-card pro-card" onClick={(e) => e.stopPropagation()}>
        {/* HUD Border Corners */}
        <div className="hud-corner top-left"></div>
        <div className="hud-corner top-right"></div>
        <div className="hud-corner bottom-left"></div>
        <div className="hud-corner bottom-right"></div>

        {/* Modal Header */}
        <div className="pcm-header">
          <div className="pcm-title-group">
            <FaExchangeAlt className="pcm-header-icon" />
            <h2 id="compare-modal-title">Playbook Comparison & Diff Analysis</h2>
            <span className="pcm-badge">V3 SENTINEL DIFF ENGINE</span>
          </div>
          <button className="pcm-close-btn" onClick={onClose} aria-label="Close compare modal">
            <FaTimes />
          </button>
        </div>

        {/* Tab Selector */}
        <div className="pcm-tabs">
          <button
            className={`pcm-tab-btn ${activeTab === "overview" ? "active" : ""}`}
            onClick={() => setActiveTab("overview")}
          >
            <FaShieldAlt className="tab-icon" /> Overview & Key Metrics
          </button>
          <button
            className={`pcm-tab-btn ${activeTab === "snort" ? "active" : ""}`}
            onClick={() => setActiveTab("snort")}
          >
            <FaFileCode className="tab-icon" /> Snort Rules Diff
            {!diff.snort_rules_identical && <span className="diff-indicator-badge">MODIFIED</span>}
          </button>
          <button
            className={`pcm-tab-btn ${activeTab === "sigma" ? "active" : ""}`}
            onClick={() => setActiveTab("sigma")}
          >
            <FaFileCode className="tab-icon" /> Sigma Rules Diff
            {!diff.sigma_rules_identical && <span className="diff-indicator-badge">MODIFIED</span>}
          </button>
          <button
            className={`pcm-tab-btn ${activeTab === "cve" ? "active" : ""}`}
            onClick={() => setActiveTab("cve")}
          >
            <FaBug className="tab-icon" /> CVE Mappings
          </button>
        </div>

        {/* Modal Body Content */}
        <div className="pcm-body">
          {loading ? (
            <div className="pcm-loading">
              <FaSpinner className="pcm-spin-icon" />
              <p>Analyzing playbook differences & compiling diff matrix...</p>
            </div>
          ) : error ? (
            <div className="pcm-error">
              <FaExclamationTriangle className="pcm-err-icon" />
              <p>{error}</p>
              <button className="pcm-btn pcm-btn-secondary" onClick={fetchComparison}>
                Retry Analysis
              </button>
            </div>
          ) : (
            <>
              {/* Playbook Header Cards Side-by-Side */}
              <div className="pcm-header-cards-grid">
                {/* Playbook 1 Card */}
                <div className="pcm-pb-card pb1">
                  <div className="pcm-pb-badge">PLAYBOOK A (# {pb1.id || id1})</div>
                  <h3 className="pcm-pb-name">{pb1.playbook_name || "Untitled Playbook A"}</h3>
                  <div className="pcm-pb-meta">
                    <span className="pcm-meta-tag technique">{pb1.technique_id || "T0000"}</span>
                    <span className={`pcm-meta-tag severity ${pb1.severity || "medium"}`}>
                      {(pb1.severity || "medium").toUpperCase()}
                    </span>
                    <span className="pcm-meta-tag score">Score: {pb1.threat_score || 50}</span>
                  </div>
                </div>

                {/* VS Indicator */}
                <div className="pcm-vs-badge">
                  <FaExchangeAlt />
                  <span>VS</span>
                </div>

                {/* Playbook 2 Card */}
                <div className="pcm-pb-card pb2">
                  <div className="pcm-pb-badge">PLAYBOOK B (# {pb2.id || id2})</div>
                  <h3 className="pcm-pb-name">{pb2.playbook_name || "Untitled Playbook B"}</h3>
                  <div className="pcm-pb-meta">
                    <span className="pcm-meta-tag technique">{pb2.technique_id || "T0000"}</span>
                    <span className={`pcm-meta-tag severity ${pb2.severity || "medium"}`}>
                      {(pb2.severity || "medium").toUpperCase()}
                    </span>
                    <span className="pcm-meta-tag score">Score: {pb2.threat_score || 50}</span>
                  </div>
                </div>
              </div>

              {/* TAB 1: OVERVIEW & METRICS DIFF */}
              {activeTab === "overview" && (
                <div className="pcm-tab-content pcm-overview-content">
                  {/* Summary Metric Diff Badges */}
                  <div className="pcm-diff-grid">
                    {/* Attack Type */}
                    <div className={`pcm-diff-card ${diff.attack_type_match ? "match" : "diff"}`}>
                      <div className="pcm-diff-label">Attack Type</div>
                      <div className="pcm-diff-values">
                        <span className="val">{pb1.attack_type || pb1.tactic || "N/A"}</span>
                        <span className="sep">vs</span>
                        <span className="val">{pb2.attack_type || pb2.tactic || "N/A"}</span>
                      </div>
                      <div className="pcm-diff-status">
                        {diff.attack_type_match ? (
                          <span className="status-match"><FaCheckCircle /> Identical</span>
                        ) : (
                          <span className="status-diff"><FaExclamationTriangle /> Different</span>
                        )}
                      </div>
                    </div>

                    {/* Technique ID */}
                    <div className={`pcm-diff-card ${diff.technique_match ? "match" : "diff"}`}>
                      <div className="pcm-diff-label">Technique ID</div>
                      <div className="pcm-diff-values">
                        <span className="val">{pb1.technique_id || "N/A"}</span>
                        <span className="sep">vs</span>
                        <span className="val">{pb2.technique_id || "N/A"}</span>
                      </div>
                      <div className="pcm-diff-status">
                        {diff.technique_match ? (
                          <span className="status-match"><FaCheckCircle /> Identical</span>
                        ) : (
                          <span className="status-diff"><FaExclamationTriangle /> Different</span>
                        )}
                      </div>
                    </div>

                    {/* Severity */}
                    <div className={`pcm-diff-card ${diff.severity_match ? "match" : "diff"}`}>
                      <div className="pcm-diff-label">Severity Level</div>
                      <div className="pcm-diff-values">
                        <span className="val">{pb1.severity || "N/A"}</span>
                        <span className="sep">vs</span>
                        <span className="val">{pb2.severity || "N/A"}</span>
                      </div>
                      <div className="pcm-diff-status">
                        {diff.severity_match ? (
                          <span className="status-match"><FaCheckCircle /> Identical</span>
                        ) : (
                          <span className="status-diff"><FaExclamationTriangle /> Different</span>
                        )}
                      </div>
                    </div>

                    {/* Confidence Score Delta */}
                    <div className="pcm-diff-card metric">
                      <div className="pcm-diff-label">Confidence Score Delta</div>
                      <div className="pcm-diff-values">
                        <span className="val">{(pb1.confidence_score || 0.9).toFixed(2)}</span>
                        <span className="sep">Δ</span>
                        <span className="val">{(pb2.confidence_score || 0.9).toFixed(2)}</span>
                      </div>
                      <div className="pcm-diff-status">
                        <span className="status-delta">
                          Diff: ±{(diff.confidence_diff || 0).toFixed(3)}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Structured Property Comparison Table */}
                  <div className="pcm-table-container">
                    <h4 className="pcm-section-title"><FaLayerGroup /> Comprehensive Field Comparison</h4>
                    <table className="pcm-table">
                      <thead>
                        <tr>
                          <th>Attribute</th>
                          <th>Playbook A (# {pb1.id || id1})</th>
                          <th>Playbook B (# {pb2.id || id2})</th>
                          <th>Comparison Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td className="field-name">Status</td>
                          <td><span className={`status-pill ${pb1.status}`}>{pb1.status}</span></td>
                          <td><span className={`status-pill ${pb2.status}`}>{pb2.status}</span></td>
                          <td>
                            {pb1.status === pb2.status ? (
                              <span className="text-match">Match</span>
                            ) : (
                              <span className="text-diff">Different</span>
                            )}
                          </td>
                        </tr>
                        <tr>
                          <td className="field-name">Threat Score</td>
                          <td>{pb1.threat_score || "—"}</td>
                          <td>{pb2.threat_score || "—"}</td>
                          <td>
                            {pb1.threat_score === pb2.threat_score ? (
                              <span className="text-match">Match</span>
                            ) : (
                              <span className="text-diff">Delta: {Math.abs((pb1.threat_score || 0) - (pb2.threat_score || 0))}</span>
                            )}
                          </td>
                        </tr>
                        <tr>
                          <td className="field-name">Source IP / IOC</td>
                          <td><code>{pb1.src_ip || "192.168.1.100"}</code></td>
                          <td><code>{pb2.src_ip || "10.0.0.45"}</code></td>
                          <td>
                            {pb1.src_ip === pb2.src_ip ? (
                              <span className="text-match">Match</span>
                            ) : (
                              <span className="text-diff">Different IOC</span>
                            )}
                          </td>
                        </tr>
                        <tr>
                          <td className="field-name">Snort Rule Text</td>
                          <td>{diff.snort_rules_identical ? "Identical signature" : "Custom signature rules"}</td>
                          <td>{diff.snort_rules_identical ? "Identical signature" : "Custom signature rules"}</td>
                          <td>
                            {diff.snort_rules_identical ? (
                              <span className="text-match">Identical</span>
                            ) : (
                              <span className="text-diff">Diff Highlights Available</span>
                            )}
                          </td>
                        </tr>
                        <tr>
                          <td className="field-name">Sigma Rule Text</td>
                          <td>{diff.sigma_rules_identical ? "Identical YAML" : "Custom YAML logic"}</td>
                          <td>{diff.sigma_rules_identical ? "Identical YAML" : "Custom YAML logic"}</td>
                          <td>
                            {diff.sigma_rules_identical ? (
                              <span className="text-match">Identical</span>
                            ) : (
                              <span className="text-diff">Diff Highlights Available</span>
                            )}
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 2: SNORT RULES DIFF */}
              {activeTab === "snort" && (
                <div className="pcm-tab-content pcm-code-diff-content">
                  <div className="pcm-diff-banner">
                    <FaFileCode />
                    <span>
                      {diff.snort_rules_identical
                        ? "Snort detection rules are 100% identical between both playbooks."
                        : "Line-by-line diff highlights for Snort detection rules:"}
                    </span>
                  </div>

                  <div className="pcm-diff-viewer">
                    <div className="diff-side left">
                      <div className="diff-header">Playbook A Snort Rule</div>
                      <pre className="diff-code">
                        {snortDiff.map((d, idx) => (
                          <div key={idx} className={`diff-line ${d.type === "del" ? "del" : d.type === "add" ? "empty" : "same"}`}>
                            <span className="line-num">{d.num1 || ""}</span>
                            <span className="line-text">{d.line1 || ""}</span>
                          </div>
                        ))}
                      </pre>
                    </div>
                    <div className="diff-side right">
                      <div className="diff-header">Playbook B Snort Rule</div>
                      <pre className="diff-code">
                        {snortDiff.map((d, idx) => (
                          <div key={idx} className={`diff-line ${d.type === "add" ? "add" : d.type === "del" ? "empty" : "same"}`}>
                            <span className="line-num">{d.num2 || ""}</span>
                            <span className="line-text">{d.line2 || ""}</span>
                          </div>
                        ))}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 3: SIGMA RULES DIFF */}
              {activeTab === "sigma" && (
                <div className="pcm-tab-content pcm-code-diff-content">
                  <div className="pcm-diff-banner">
                    <FaFileCode />
                    <span>
                      {diff.sigma_rules_identical
                        ? "Sigma detection rules are 100% identical between both playbooks."
                        : "Line-by-line diff highlights for Sigma detection rules:"}
                    </span>
                  </div>

                  <div className="pcm-diff-viewer">
                    <div className="diff-side left">
                      <div className="diff-header">Playbook A Sigma YAML</div>
                      <pre className="diff-code">
                        {sigmaDiff.map((d, idx) => (
                          <div key={idx} className={`diff-line ${d.type === "del" ? "del" : d.type === "add" ? "empty" : "same"}`}>
                            <span className="line-num">{d.num1 || ""}</span>
                            <span className="line-text">{d.line1 || ""}</span>
                          </div>
                        ))}
                      </pre>
                    </div>
                    <div className="diff-side right">
                      <div className="diff-header">Playbook B Sigma YAML</div>
                      <pre className="diff-code">
                        {sigmaDiff.map((d, idx) => (
                          <div key={idx} className={`diff-line ${d.type === "add" ? "add" : d.type === "del" ? "empty" : "same"}`}>
                            <span className="line-num">{d.num2 || ""}</span>
                            <span className="line-text">{d.line2 || ""}</span>
                          </div>
                        ))}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 4: CVE MAPPINGS */}
              {activeTab === "cve" && (
                <div className="pcm-tab-content pcm-cve-content">
                  <div className="pcm-cve-grid">
                    {/* Playbook A CVEs */}
                    <div className="pcm-cve-card">
                      <h4>Playbook A CVE Vulnerabilities ({cve1.length})</h4>
                      {cve1.length === 0 ? (
                        <div className="cve-empty">No associated CVE mappings found.</div>
                      ) : (
                        <div className="cve-list">
                          {cve1.map((item, idx) => (
                            <div key={idx} className="cve-item">
                              <span className="cve-id">{item.cve_id || item}</span>
                              <span className="cve-score">CVSS {item.cvss_score || "7.5"}</span>
                              <p className="cve-desc">{item.description || "Known vulnerability mapping"}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Playbook B CVEs */}
                    <div className="pcm-cve-card">
                      <h4>Playbook B CVE Vulnerabilities ({cve2.length})</h4>
                      {cve2.length === 0 ? (
                        <div className="cve-empty">No associated CVE mappings found.</div>
                      ) : (
                        <div className="cve-list">
                          {cve2.map((item, idx) => (
                            <div key={idx} className="cve-item">
                              <span className="cve-id">{item.cve_id || item}</span>
                              <span className="cve-score">CVSS {item.cvss_score || "7.5"}</span>
                              <p className="cve-desc">{item.description || "Known vulnerability mapping"}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="pcm-footer">
          <div className="pcm-footer-info">
            <FaInfoCircle /> Comparing Playbook #{pb1.id || id1} and #{pb2.id || id2}
          </div>

          <div className="pcm-footer-actions">
            <button className="pcm-btn pcm-btn-secondary" onClick={onClose}>
              Close Diff Modal
            </button>
            {onApprove && pb1.id && (
              <button
                className="pcm-btn pcm-btn-success"
                onClick={() => onApprove(pb1.id)}
              >
                <FaCheck /> Approve Playbook A
              </button>
            )}
            {onApprove && pb2.id && (
              <button
                className="pcm-btn pcm-btn-success"
                onClick={() => onApprove(pb2.id)}
              >
                <FaCheck /> Approve Playbook B
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

PlaybookCompareModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  id1: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
  id2: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
  playbook1: PropTypes.object,
  playbook2: PropTypes.object,
  onApprove: PropTypes.func,
  onReject: PropTypes.func,
  addToast: PropTypes.func,
};
