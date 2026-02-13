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
  FaDocker
} from "react-icons/fa";
import {
  SiTensorflow,
  SiFastapi,
  SiPostgresql,
  SiTailwindcss,
  SiScikitlearn
} from "react-icons/si";
import "../styles/pages/About.css";

const About = () => {
  const features = [
    {
      icon: FaBrain,
      title: "AI-Powered Detection",
      description: "Advanced machine learning models trained on real network traffic to detect threats with high accuracy."
    },
    {
      icon: FaNetworkWired,
      title: "Honeypot Mesh Network",
      description: "Distributed honeypot infrastructure simulating SSH, HTTP, FTP, and SMTP services to attract and analyze attacks."
    },
    {
      icon: FaChartLine,
      title: "Real-time Monitoring",
      description: "Live dashboard with instant threat visualization, packet analysis, and security event tracking."
    },
    {
      icon: FaLock,
      title: "Active Defense",
      description: "Automated threat response capabilities including IP blocking and traffic filtering."
    },
    {
      icon: FaDatabase,
      title: "Comprehensive Logging",
      description: "Detailed logging of all network events, attack patterns, and threat intelligence data."
    },
    {
      icon: FaRocket,
      title: "High Performance",
      description: "Optimized packet processing pipeline capable of handling millions of events per day."
    }
  ];

  const techStack = [
    { icon: FaPython, name: "Python", category: "Backend" },
    { icon: SiFastapi, name: "FastAPI", category: "API" },
    { icon: SiPostgresql, name: "PostgreSQL", category: "Database" },
    { icon: SiTensorflow, name: "TensorFlow", category: "ML" },
    { icon: SiScikitlearn, name: "Scikit-learn", category: "ML" },
    { icon: FaReact, name: "React", category: "Frontend" },
    { icon: SiTailwindcss, name: "Tailwind CSS", category: "Styling" },
    { icon: FaDocker, name: "Docker", category: "DevOps" },
  ];

  const stats = [
    { value: "99.2%", label: "Detection Accuracy" },
    { value: "7M+", label: "Events Processed" },
    { value: "<50ms", label: "Response Time" },
    { value: "24/7", label: "Monitoring" }
  ];

  const architecture = [
    { layer: "Presentation", items: ["React Dashboard", "Real-time Visualization", "Responsive UI"] },
    { layer: "API Layer", items: ["FastAPI REST Endpoints", "WebSocket Connections", "Authentication"] },
    { layer: "Business Logic", items: ["ML Inference Engine", "Threat Classification", "Feature Extraction"] },
    { layer: "Data Layer", items: ["PostgreSQL Database", "Event Logging", "Statistics Aggregation"] },
    { layer: "Collection", items: ["Honeypot Services", "Packet Sniffer", "Traffic Analysis"] }
  ];

  return (
    <div className="about-wrapper">
      {/* Hero Section */}
      <section className="about-hero">
        <div className="hero-background">
          <div className="hero-gradient"></div>
          <div className="hero-grid"></div>
        </div>
        <div className="hero-content">
          <div className="hero-badge">
            <FaShieldAlt />
            <span>AI-Powered Cybersecurity</span>
          </div>
          <h1>PhantomNet</h1>
          <p className="hero-subtitle">
            Next-Generation Adaptive Honeypot System with Machine Learning-Driven Threat Detection
          </p>
          <div className="hero-stats">
            {stats.map((stat, i) => (
              <div key={i} className="stat-item">
                <span className="stat-value">{stat.value}</span>
                <span className="stat-label">{stat.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Overview Section */}
      <section className="about-section">
        <div className="section-header">
          <h2>Project Overview</h2>
          <p>Understanding the PhantomNet System</p>
        </div>
        <div className="overview-content">
          <div className="overview-text">
            <p>
              <strong>PhantomNet</strong> is an advanced cybersecurity platform that combines honeypot technology
              with artificial intelligence to detect, analyze, and respond to network threats in real-time.
            </p>
            <p>
              The system deploys a mesh of honeypot services that simulate vulnerable network endpoints,
              attracting potential attackers and capturing their techniques. All collected traffic is
              processed through our machine learning pipeline, which classifies threats and provides
              actionable security intelligence.
            </p>
            <p>
              Unlike traditional signature-based detection systems, PhantomNet uses behavioral analysis
              and anomaly detection to identify zero-day attacks and novel threat patterns, making it
              an essential tool for modern security operations.
            </p>
          </div>
          <div className="overview-diagram">
            <div className="diagram-box threat">Threats</div>
            <div className="diagram-arrow">↓</div>
            <div className="diagram-box honeypot">Honeypot Mesh</div>
            <div className="diagram-arrow">↓</div>
            <div className="diagram-box ml">ML Analysis</div>
            <div className="diagram-arrow">↓</div>
            <div className="diagram-box dashboard">Dashboard</div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="about-section">
        <div className="section-header">
          <h2>Key Features</h2>
          <p>Powerful capabilities for comprehensive threat detection</p>
        </div>
        <div className="features-grid">
          {features.map((feature, i) => {
            const Icon = feature.icon;
            return (
              <div key={i} className="feature-card">
                <div className="feature-icon">
                  <Icon />
                </div>
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Architecture Section */}
      <section className="about-section">
        <div className="section-header">
          <h2>System Architecture</h2>
          <p>Multi-layered defense system design</p>
        </div>
        <div className="architecture-diagram">
          {architecture.map((layer, i) => (
            <div key={i} className="arch-layer">
              <div className="layer-name">{layer.layer}</div>
              <div className="layer-items">
                {layer.items.map((item, j) => (
                  <span key={j} className="layer-item">{item}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Tech Stack Section */}
      <section className="about-section">
        <div className="section-header">
          <h2>Technology Stack</h2>
          <p>Built with modern, industry-leading technologies</p>
        </div>
        <div className="tech-grid">
          {techStack.map((tech, i) => {
            const Icon = tech.icon;
            return (
              <div key={i} className="tech-card">
                <Icon className="tech-icon" />
                <span className="tech-name">{tech.name}</span>
                <span className="tech-category">{tech.category}</span>
              </div>
            );
          })}
        </div>
      </section>

      {/* ML Pipeline Section */}
      <section className="about-section">
        <div className="section-header">
          <h2>ML Pipeline</h2>
          <p>How our machine learning system processes threats</p>
        </div>
        <div className="ml-pipeline">
          <div className="pipeline-step">
            <div className="step-number">1</div>
            <h4>Data Collection</h4>
            <p>Raw packet capture from honeypot services with metadata extraction</p>
          </div>
          <div className="pipeline-connector"></div>
          <div className="pipeline-step">
            <div className="step-number">2</div>
            <h4>Feature Extraction</h4>
            <p>Statistical features, protocol analysis, behavioral patterns</p>
          </div>
          <div className="pipeline-connector"></div>
          <div className="pipeline-step">
            <div className="step-number">3</div>
            <h4>Classification</h4>
            <p>Multi-class threat classification using ensemble models</p>
          </div>
          <div className="pipeline-connector"></div>
          <div className="pipeline-step">
            <div className="step-number">4</div>
            <h4>Response</h4>
            <p>Automated alerting and active defense measures</p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="about-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <FaShieldAlt className="footer-logo" />
            <span>PhantomNet</span>
          </div>
          <p>Advanced Honeypot System with AI-Powered Threat Detection</p>
          <div className="footer-links">
            <a href="#"><FaGithub /> GitHub</a>
            <a href="#"><FaCode /> Documentation</a>
            <a href="#"><FaLinkedin /> LinkedIn</a>
          </div>
          <p className="footer-copyright">© 2026 PhantomNet Project. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
};

export default About;