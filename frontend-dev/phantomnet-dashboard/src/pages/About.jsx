import React, { useState, useEffect, useRef } from "react";
import {
  FaShieldAlt,
  FaBrain,
  FaNetworkWired,
  FaDatabase,
  FaChartLine,
  FaLock,
  FaRocket,
  FaCode,
  FaServer,
  FaGithub,
  FaLinkedin,
  FaPython,
  FaReact,
  FaDocker,
  FaCrosshairs,
  FaMapMarkedAlt,
  FaFileAlt,
  FaUserShield,
  FaSearch,
  FaCogs,
  FaExchangeAlt,
  FaChevronRight,
  FaStar,
  FaCheck,
  FaProjectDiagram,
  FaBolt,
  FaLayerGroup,
} from "react-icons/fa";
import "../Styles/pages/About.css";

/* ─── Animated counter hook ─── */
const useCounter = (target, duration = 2000) => {
  const [count, setCount] = useState(0);
  const ref = useRef(null);
  const started = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started.current) {
          started.current = true;
          const start = performance.now();
          const numTarget =
            typeof target === "number"
              ? target
              : parseFloat(target.replace(/[^0-9.]/g, ""));

          const tick = (now) => {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            setCount(Math.floor(eased * numTarget));
            if (progress < 1) requestAnimationFrame(tick);
            else setCount(numTarget);
          };
          requestAnimationFrame(tick);
        }
      },
      { threshold: 0.3 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [target, duration]);

  return [count, ref];
};

/* ─── Static data ─── */
const HERO_STATS = [
  { value: "99.2%", label: "Detection Accuracy", numericValue: 99.2 },
  { value: "12", label: "ML Models", numericValue: 12 },
  { value: "<12ms", label: "Inference Latency", numericValue: 12 },
  { value: "24/7", label: "Autonomous Monitoring", numericValue: 24 },
  { value: "4", label: "Honeypot Services", numericValue: 4 },
  { value: "20+", label: "REST APIs", numericValue: 20 },
];

const CORE_CAPABILITIES = [
  {
    icon: FaBrain,
    title: "ML-Driven Threat Scoring",
    description:
      "Ensemble ML pipeline combining Random Forest, Isolation Forest, and LSTM networks for multi-class threat classification with SHAP explainability.",
    tags: ["Random Forest", "Isolation Forest", "LSTM", "SHAP"],
  },
  {
    icon: FaNetworkWired,
    title: "Multi-Protocol Honeypot Mesh",
    description:
      "Four concurrent deception services (SSH, HTTP, FTP, SMTP) simulating vulnerable endpoints to attract, engage, and fingerprint attacker TTPs.",
    tags: ["SSH", "HTTP", "FTP", "SMTP"],
  },
  {
    icon: FaChartLine,
    title: "Real-Time Event Streaming",
    description:
      "WebSocket-powered live dashboard broadcasting packet events, metrics, and alerts every 2 seconds with in-memory caching layer for sub-15ms reads.",
    tags: ["WebSocket", "Event Stream", "Live Metrics"],
  },
  {
    icon: FaLock,
    title: "Automated Response Engine",
    description:
      "Policy-based response executor that automatically blocks malicious IPs, rate-limits suspicious traffic, and triggers escalation playbooks.",
    tags: ["IP Blocking", "Rate Limiting", "Playbooks"],
  },
  {
    icon: FaMapMarkedAlt,
    title: "GeoIP Attack Mapping",
    description:
      "IP geolocation enrichment with interactive global attack map, country heatmaps, and city-level drill-down using MaxMind GeoLite2 with API fallback.",
    tags: ["MaxMind", "Attack Map", "GeoIP"],
  },
  {
    icon: FaCrosshairs,
    title: "Threat Hunting & IOC Management",
    description:
      "Advanced query builder for proactive threat hunting with IOC watchlists (IP, Domain, Hash, URL), investigation case management, and evidence linking.",
    tags: ["IOC", "Threat Hunting", "Case Management"],
  },
  {
    icon: FaProjectDiagram,
    title: "Attack Campaign Clustering",
    description:
      "Unsupervised clustering engine that groups related attack events into coordinated campaigns using behavioral similarity analysis.",
    tags: ["Clustering", "Campaign Detection", "DBSCAN"],
  },
  {
    icon: FaFileAlt,
    title: "PCAP Deep Packet Inspection",
    description:
      "Full packet capture with protocol-aware analysis, threat pattern detection, export capabilities, and configurable 30-day retention with auto-cleanup.",
    tags: ["PCAP", "DPI", "Protocol Analysis"],
  },
  {
    icon: FaExchangeAlt,
    title: "SIEM & STIX Integration",
    description:
      "Universal SIEM exporter supporting Splunk, Elasticsearch, and QRadar with STIX 2.1 threat intelligence format for cross-platform interoperability.",
    tags: ["Splunk", "Elasticsearch", "STIX 2.1"],
  },
];

const ARCHITECTURE_LAYERS = [
  {
    layer: "Presentation Layer",
    color: "#3b82f6",
    items: [
      "React 18 SPA",
      "Real-Time WebSocket Dashboard",
      "Interactive Attack Map",
      "Dark/Light Theme",
      "Responsive Design",
    ],
  },
  {
    layer: "API Gateway",
    color: "#8b5cf6",
    items: [
      "FastAPI REST (20+ endpoints)",
      "WebSocket Event Streams",
      "JWT Authentication",
      "RBAC Authorization",
      "Response Caching",
    ],
  },
  {
    layer: "Intelligence Engine",
    color: "#ec4899",
    items: [
      "Ensemble ML Scoring",
      "SHAP Explainability",
      "Campaign Clustering",
      "Anomaly Detection",
      "Threat Correlation",
    ],
  },
  {
    layer: "Service Mesh",
    color: "#f59e0b",
    items: [
      "Threat Analyzer",
      "Response Executor",
      "GeoIP Enrichment",
      "PCAP Analyzer",
      "SIEM Exporter",
    ],
  },
  {
    layer: "Data Layer",
    color: "#22c55e",
    items: [
      "SQLite / PostgreSQL",
      "SQLAlchemy ORM",
      "12-Table Schema",
      "Event Logging",
      "Statistics Aggregation",
    ],
  },
  {
    layer: "Collection Layer",
    color: "#06b6d4",
    items: [
      "Scapy Packet Sniffer",
      "SSH Honeypot",
      "HTTP Honeypot",
      "FTP Honeypot",
      "SMTP Honeypot",
    ],
  },
];

const TECH_STACK = [
  {
    icon: FaPython,
    name: "Python 3.11",
    category: "Backend",
    desc: "Core runtime",
  },
  {
    icon: FaBolt,
    name: "FastAPI",
    category: "REST API",
    desc: "Async framework",
  },
  {
    icon: FaReact,
    name: "React 18",
    category: "Frontend",
    desc: "SPA framework",
  },
  {
    icon: FaDatabase,
    name: "SQLite",
    category: "Database",
    desc: "Embedded DB",
  },
  {
    icon: FaBrain,
    name: "Scikit-learn",
    category: "ML",
    desc: "Model training",
  },
  {
    icon: FaLayerGroup,
    name: "MLflow",
    category: "MLOps",
    desc: "Model registry",
  },
  {
    icon: FaNetworkWired,
    name: "WebSockets",
    category: "Real-Time",
    desc: "Live streams",
  },
  {
    icon: FaDocker,
    name: "Docker",
    category: "DevOps",
    desc: "Containerization",
  },
];

const ML_PIPELINE_STEPS = [
  {
    step: 1,
    title: "Packet Capture",
    subtitle: "Collection Layer",
    details: [
      "Scapy NIC-level packet interception",
      "Protocol feature extraction (IP, TCP, UDP, ICMP)",
      "Metadata enrichment: ports, length, flags",
      "Honeypot session correlation",
    ],
  },
  {
    step: 2,
    title: "Feature Engineering",
    subtitle: "Preprocessing",
    details: [
      "50+ statistical features computed",
      "Protocol one-hot encoding",
      "Port frequency analysis",
      "Temporal pattern extraction",
    ],
  },
  {
    step: 3,
    title: "Ensemble Scoring",
    subtitle: "Inference Engine",
    details: [
      "Random Forest primary classifier",
      "Isolation Forest anomaly detection",
      "LSTM sequence analysis",
      "Weighted ensemble aggregation",
    ],
  },
  {
    step: 4,
    title: "Threat Classification",
    subtitle: "Decision Layer",
    details: [
      "Multi-class: DDoS, PortScan, BruteForce, etc.",
      "Threat level: LOW → MEDIUM → HIGH → CRITICAL",
      "Confidence scoring (0.0 – 1.0)",
      "SHAP feature attribution",
    ],
  },
  {
    step: 5,
    title: "Automated Response",
    subtitle: "Action Layer",
    details: [
      "Policy-based IP blocking",
      "Alert escalation playbooks",
      "SIEM event export",
      "Analyst notification pipeline",
    ],
  },
];

const SECURITY_FEATURES = [
  {
    icon: FaUserShield,
    title: "Role-Based Access Control",
    desc: "Three-tier RBAC (Admin, Analyst, Viewer) with JWT authentication, session management, and granular API authorization.",
  },
  {
    icon: FaSearch,
    title: "Proactive Threat Hunting",
    desc: "Advanced query builder with multi-field search, IOC correlation, IP/Domain/Hash watchlists, and investigation case management.",
  },
  {
    icon: FaCogs,
    title: "Configurable Response Policies",
    desc: "Tunable ML thresholds, deception modes (aggressive/balanced/stealth), alert severity filters, and SIEM export frequencies from the admin panel.",
  },
  {
    icon: FaDatabase,
    title: "Audit & Compliance",
    desc: "Security logging middleware, request profiling, full response action history, automated database backups, and configurable data retention.",
  },
];

const PROJECT_MILESTONES = [
  {
    phase: "Phase 1",
    title: "Foundation",
    status: "complete",
    items: [
      "Core sniffer & ML pipeline",
      "React dashboard with live traffic",
      "FastAPI REST backend",
      "SQLite database schema",
    ],
  },
  {
    phase: "Phase 2",
    title: "Intelligence",
    status: "complete",
    items: [
      "Multi-protocol honeypots (SSH, HTTP, FTP, SMTP)",
      "GeoIP enrichment & attack mapping",
      "Threat correlation engine",
      "PCAP deep packet capture",
    ],
  },
  {
    phase: "Phase 3",
    title: "Advanced Defense",
    status: "complete",
    items: [
      "Automated response executor",
      "SIEM/STIX integration",
      "Admin panel with RBAC",
      "Threat hunting & IOC management",
    ],
  },
  {
    phase: "Phase 4",
    title: "ML Excellence",
    status: "active",
    items: [
      "Ensemble model stacking",
      "SHAP explainability",
      "Campaign clustering",
      "Continuous retraining pipeline",
    ],
  },
];

/* ───────────────────── Component ───────────────────── */
const About = () => {
  const [activeArch, setActiveArch] = useState(0);
  const [activePipeline, setActivePipeline] = useState(0);

  /* animated counters for hero stats */
  const [c0, r0] = useCounter(99, 1800);
  const [c1, r1] = useCounter(12, 1400);
  const [c2, r2] = useCounter(12, 1200);
  const [c3, r3] = useCounter(24, 1600);
  const [c4, r4] = useCounter(4, 1000);
  const [c5, r5] = useCounter(20, 1400);
  const counterRefs = [r0, r1, r2, r3, r4, r5];
  const counterVals = [
    `${c0}.2%`,
    c1,
    `<${c2}ms`,
    `${c3}/7`,
    c4,
    `${c5}+`,
  ];

  return (
    <div className="about-wrapper">
      {/* ═══════════════ HERO ═══════════════ */}
      <section className="about-hero">
        <div className="hero-background">
          <div className="hero-gradient"></div>
          <div className="hero-grid"></div>
          <div className="hero-particles">
            {[...Array(20)].map((_, i) => (
              <span
                key={i}
                className="particle"
                style={{
                  left: `${Math.random() * 100}%`,
                  animationDelay: `${Math.random() * 5}s`,
                  animationDuration: `${6 + Math.random() * 8}s`,
                }}
              />
            ))}
          </div>
        </div>
        <div className="hero-content">
          <div className="hero-badge">
            <FaShieldAlt />
            <span>AI-Powered Active Defense Platform</span>
          </div>
          <h1>PhantomNet</h1>
          <p className="hero-subtitle">
            Next-Generation Adaptive Honeypot System with Machine
            Learning‑Driven Threat Detection, Automated Response, and
            Enterprise-Grade Security Intelligence
          </p>
          <p className="hero-tagline">
            Deception. Detection. Defense. — All in Real‑Time.
          </p>
          <div className="hero-stats">
            {HERO_STATS.map((stat, i) => (
              <div key={i} className="stat-item" ref={counterRefs[i]}>
                <span className="stat-value">{counterVals[i]}</span>
                <span className="stat-label">{stat.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════ OVERVIEW ═══════════════ */}
      <section className="about-section">
        <div className="section-header">
          <div className="section-badge">Overview</div>
          <h2>What is PhantomNet?</h2>
          <p>An AI-native cybersecurity platform purpose-built for modern threat landscapes</p>
        </div>
        <div className="overview-content">
          <div className="overview-text">
            <p>
              <strong>PhantomNet</strong> is a full-stack cybersecurity platform
              that unifies honeypot deception technology, machine learning threat
              analysis, and automated incident response into a single
              operational console. Designed for SOC analysts, threat hunters, and
              security researchers, it transforms raw network traffic into
              actionable intelligence.
            </p>
            <p>
              The platform deploys a mesh of four concurrent honeypot
              services — SSH, HTTP, FTP, and SMTP — that simulate vulnerable
              endpoints to attract and fingerprint attacker Tactics, Techniques,
              and Procedures (TTPs). Every captured packet flows through an
              ensemble machine learning pipeline that classifies threats across
              multiple categories including DDoS, port scanning, brute force,
              and zero-day anomalies.
            </p>
            <p>
              Unlike signature-based IDS/IPS systems, PhantomNet's behavioral
              analysis engine detects previously unseen attack patterns through
              statistical anomaly detection and temporal sequence modeling,
              achieving <strong>99.2% classification accuracy</strong> with
              sub‑12ms inference latency.
            </p>
            <div className="overview-highlights">
              <div className="highlight-item">
                <FaCheck />
                <span>Open-source & self-hostable</span>
              </div>
              <div className="highlight-item">
                <FaCheck />
                <span>Zero external API dependencies for core detection</span>
              </div>
              <div className="highlight-item">
                <FaCheck />
                <span>STIX 2.1 compatible threat intelligence export</span>
              </div>
              <div className="highlight-item">
                <FaCheck />
                <span>Enterprise SIEM integration (Splunk, ELK, QRadar)</span>
              </div>
            </div>
          </div>
          <div className="overview-diagram">
            <div className="diagram-box threat">
              <span className="diagram-icon">⚠️</span>
              <span>Threats & Attackers</span>
            </div>
            <div className="diagram-arrow">
              <div className="arrow-line pulse" />
            </div>
            <div className="diagram-box honeypot">
              <span className="diagram-icon">🍯</span>
              <span>Honeypot Mesh</span>
              <small>SSH · HTTP · FTP · SMTP</small>
            </div>
            <div className="diagram-arrow">
              <div className="arrow-line pulse delay-1" />
            </div>
            <div className="diagram-box ml">
              <span className="diagram-icon">🧠</span>
              <span>ML Scoring Engine</span>
              <small>RF · IF · LSTM · SHAP</small>
            </div>
            <div className="diagram-arrow">
              <div className="arrow-line pulse delay-2" />
            </div>
            <div className="diagram-box response">
              <span className="diagram-icon">🛡️</span>
              <span>Automated Response</span>
              <small>Block · Alert · Escalate</small>
            </div>
            <div className="diagram-arrow">
              <div className="arrow-line pulse delay-3" />
            </div>
            <div className="diagram-box dashboard">
              <span className="diagram-icon">📊</span>
              <span>SOC Dashboard</span>
              <small>Real-Time · Hunt · Report</small>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════ CAPABILITIES ═══════════════ */}
      <section className="about-section">
        <div className="section-header">
          <div className="section-badge">Capabilities</div>
          <h2>Core Security Capabilities</h2>
          <p>Nine integrated subsystems powering a complete defense‑in‑depth architecture</p>
        </div>
        <div className="features-grid">
          {CORE_CAPABILITIES.map((feat, i) => {
            const Icon = feat.icon;
            return (
              <div key={i} className="feature-card" style={{ animationDelay: `${i * 0.06}s` }}>
                <div className="feature-icon">
                  <Icon />
                </div>
                <h3>{feat.title}</h3>
                <p>{feat.description}</p>
                <div className="feature-tags">
                  {feat.tags.map((tag, j) => (
                    <span key={j} className="feature-tag">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ═══════════════ ARCHITECTURE ═══════════════ */}
      <section className="about-section">
        <div className="section-header">
          <div className="section-badge">Architecture</div>
          <h2>System Architecture</h2>
          <p>Six-layer defense-in-depth architecture with full data lineage</p>
        </div>
        <div className="architecture-interactive">
          <div className="arch-nav">
            {ARCHITECTURE_LAYERS.map((layer, i) => (
              <button
                key={i}
                className={`arch-nav-btn ${activeArch === i ? "active" : ""}`}
                onClick={() => setActiveArch(i)}
                style={{
                  "--layer-color": layer.color,
                  borderLeftColor: activeArch === i ? layer.color : "transparent",
                }}
              >
                <span className="arch-dot" style={{ background: layer.color }} />
                {layer.layer}
              </button>
            ))}
          </div>
          <div className="arch-detail">
            <h3 style={{ color: ARCHITECTURE_LAYERS[activeArch].color }}>
              {ARCHITECTURE_LAYERS[activeArch].layer}
            </h3>
            <div className="arch-chips">
              {ARCHITECTURE_LAYERS[activeArch].items.map((item, j) => (
                <div
                  key={j}
                  className="arch-chip"
                  style={{
                    borderColor: ARCHITECTURE_LAYERS[activeArch].color + "40",
                    background: ARCHITECTURE_LAYERS[activeArch].color + "10",
                  }}
                >
                  <FaChevronRight
                    size={10}
                    style={{ color: ARCHITECTURE_LAYERS[activeArch].color }}
                  />
                  {item}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Compact stacked diagram */}
        <div className="architecture-diagram">
          {ARCHITECTURE_LAYERS.map((layer, i) => (
            <div
              key={i}
              className={`arch-layer ${activeArch === i ? "arch-active" : ""}`}
              onClick={() => setActiveArch(i)}
              style={{ borderLeftColor: layer.color }}
            >
              <div className="layer-name">{layer.layer}</div>
              <div className="layer-items">
                {layer.items.map((item, j) => (
                  <span key={j} className="layer-item">
                    {item}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ═══════════════ TECH STACK ═══════════════ */}
      <section className="about-section">
        <div className="section-header">
          <div className="section-badge">Technology</div>
          <h2>Technology Stack</h2>
          <p>Production-grade, industry-standard technologies</p>
        </div>
        <div className="tech-grid">
          {TECH_STACK.map((tech, i) => {
            const Icon = tech.icon;
            return (
              <div key={i} className="tech-card">
                <Icon className="tech-icon" />
                <span className="tech-name">{tech.name}</span>
                <span className="tech-desc">{tech.desc}</span>
                <span className="tech-category">{tech.category}</span>
              </div>
            );
          })}
        </div>
      </section>

      {/* ═══════════════ ML PIPELINE ═══════════════ */}
      <section className="about-section">
        <div className="section-header">
          <div className="section-badge">Machine Learning</div>
          <h2>ML Inference Pipeline</h2>
          <p>End-to-end threat classification in under 12 milliseconds</p>
        </div>
        <div className="pipeline-interactive">
          <div className="pipeline-steps-nav">
            {ML_PIPELINE_STEPS.map((step, i) => (
              <button
                key={i}
                className={`pipe-nav-btn ${activePipeline === i ? "active" : ""}`}
                onClick={() => setActivePipeline(i)}
              >
                <span className="pipe-num">{step.step}</span>
                <div className="pipe-labels">
                  <span className="pipe-title">{step.title}</span>
                  <span className="pipe-sub">{step.subtitle}</span>
                </div>
              </button>
            ))}
          </div>
          <div className="pipeline-detail">
            <div className="pipeline-detail-header">
              <span className="detail-step-num">
                {ML_PIPELINE_STEPS[activePipeline].step}
              </span>
              <div>
                <h4>{ML_PIPELINE_STEPS[activePipeline].title}</h4>
                <span className="detail-subtitle">
                  {ML_PIPELINE_STEPS[activePipeline].subtitle}
                </span>
              </div>
            </div>
            <ul className="pipeline-detail-list">
              {ML_PIPELINE_STEPS[activePipeline].details.map((d, j) => (
                <li key={j}>
                  <FaChevronRight size={10} />
                  {d}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Compact horizontal pipeline */}
        <div className="ml-pipeline">
          {ML_PIPELINE_STEPS.map((step, i) => (
            <React.Fragment key={i}>
              <div
                className={`pipeline-step ${activePipeline === i ? "step-active" : ""}`}
                onClick={() => setActivePipeline(i)}
              >
                <div className="step-number">{step.step}</div>
                <h4>{step.title}</h4>
                <p>{step.subtitle}</p>
              </div>
              {i < ML_PIPELINE_STEPS.length - 1 && (
                <div className="pipeline-connector" />
              )}
            </React.Fragment>
          ))}
        </div>
      </section>

      {/* ═══════════════ SECURITY ═══════════════ */}
      <section className="about-section">
        <div className="section-header">
          <div className="section-badge">Security</div>
          <h2>Security & Compliance</h2>
          <p>Enterprise-grade access control, auditing, and data governance</p>
        </div>
        <div className="security-grid">
          {SECURITY_FEATURES.map((feat, i) => {
            const Icon = feat.icon;
            return (
              <div key={i} className="security-card">
                <div className="security-icon">
                  <Icon />
                </div>
                <div className="security-text">
                  <h4>{feat.title}</h4>
                  <p>{feat.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ═══════════════ ROADMAP ═══════════════ */}
      <section className="about-section">
        <div className="section-header">
          <div className="section-badge">Roadmap</div>
          <h2>Development Roadmap</h2>
          <p>Phased delivery across an 8-month development lifecycle</p>
        </div>
        <div className="roadmap-timeline">
          {PROJECT_MILESTONES.map((phase, i) => (
            <div
              key={i}
              className={`roadmap-item ${phase.status === "active" ? "roadmap-active" : ""} ${phase.status === "complete" ? "roadmap-complete" : ""}`}
            >
              <div className="roadmap-marker">
                <div className="marker-dot">
                  {phase.status === "complete" ? (
                    <FaCheck size={10} />
                  ) : (
                    <FaStar size={10} />
                  )}
                </div>
                {i < PROJECT_MILESTONES.length - 1 && (
                  <div className="marker-line" />
                )}
              </div>
              <div className="roadmap-content">
                <div className="roadmap-phase">{phase.phase}</div>
                <h4>{phase.title}</h4>
                <ul>
                  {phase.items.map((item, j) => (
                    <li key={j}>{item}</li>
                  ))}
                </ul>
                <span
                  className={`roadmap-status ${phase.status === "complete" ? "status-done" : "status-active"}`}
                >
                  {phase.status === "complete" ? "COMPLETED" : "IN PROGRESS"}
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ═══════════════ DATABASE SCHEMA ═══════════════ */}
      <section className="about-section">
        <div className="section-header">
          <div className="section-badge">Data Model</div>
          <h2>Database Schema</h2>
          <p>12 relational tables powering the intelligence engine</p>
        </div>
        <div className="schema-grid">
          {[
            { name: "packet_logs", desc: "Network packet events with ML scoring", cols: "14 columns" },
            { name: "alerts", desc: "Correlated security alerts with GeoIP", cols: "12 columns" },
            { name: "events", desc: "Honeypot interaction sessions", cols: "10 columns" },
            { name: "attack_sessions", desc: "Attacker session tracking", cols: "4 columns" },
            { name: "iocs", desc: "Indicators of Compromise watchlist", cols: "9 columns" },
            { name: "investigation_cases", desc: "Analyst case management", cols: "8 columns" },
            { name: "pcap_captures", desc: "Packet capture metadata", cols: "10 columns" },
            { name: "scheduled_reports", desc: "Automated report scheduler", cols: "11 columns" },
            { name: "users", desc: "RBAC user accounts", cols: "8 columns" },
            { name: "system_config", desc: "Runtime configuration store", cols: "5 columns" },
            { name: "honeypot_nodes", desc: "Honeypot node registry", cols: "7 columns" },
            { name: "policies", desc: "Deception policy definitions", cols: "5 columns" },
          ].map((tbl, i) => (
            <div key={i} className="schema-card">
              <code className="schema-name">{tbl.name}</code>
              <span className="schema-desc">{tbl.desc}</span>
              <span className="schema-cols">{tbl.cols}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ═══════════════ FOOTER ═══════════════ */}
      <footer className="about-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <FaShieldAlt className="footer-logo" />
            <span>PhantomNet</span>
          </div>
          <p className="footer-desc">
            AI-Powered Active Defense Platform — Deception Technology Meets
            Machine Learning
          </p>
          <div className="footer-meta">
            <div className="meta-item">
              <span className="meta-label">Version</span>
              <span className="meta-value">2.0.0</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">License</span>
              <span className="meta-value">MIT</span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Status</span>
              <span className="meta-value status-live">● Active</span>
            </div>
          </div>
          <div className="footer-links">
            <a href="https://github.com/sriram21-09/PhantomNet" target="_blank" rel="noopener noreferrer">
              <FaGithub /> GitHub
            </a>
            <a href="#"><FaCode /> Documentation</a>
            <a href="#"><FaLinkedin /> LinkedIn</a>
          </div>
          <p className="footer-copyright">
            © {new Date().getFullYear()} PhantomNet Project — Built with 🔒 for
            the cybersecurity community
          </p>
        </div>
      </footer>
    </div>
  );
};

export default About;