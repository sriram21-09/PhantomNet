import { Link, useLocation, useNavigate } from "react-router-dom";
import { useState, useEffect } from "react";
import ThemeToggle from "./ThemeToggle";
import { useAuth } from "../context/AuthContext";
import {
  FaShieldAlt,
  FaTachometerAlt,
  FaExclamationTriangle,
  FaListAlt,
  FaInfoCircle,
  FaNetworkWired,
  FaChartBar,
  FaSearch,
  FaDatabase,
  FaLock,
  FaBrain,
  FaExclamationCircle,
  FaCog,
  FaEye,
  FaChevronDown,
  FaSignOutAlt,
  FaUserShield
} from "react-icons/fa";
import "../Styles/components/Navbar.css";

const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, isAuthenticated, logout } = useAuth();
  const [pendingCount, setPendingCount] = useState(0);

  /* Fetch Sentinel stats on mount and route changes */
  useEffect(() => {
    const fetchSentinelStats = async () => {
      try {
        const res = await fetch("/api/sentinel/stats");
        const data = await res.json();
        if (res.ok && data.status === "success") {
          setPendingCount(data.pending || 0);
        }
      } catch {
        // Hide badge if stats unavailable
        setPendingCount(0);
      }
    };
    fetchSentinelStats();
  }, [location.pathname]);

  const navLinks = [
    { path: "/dashboard", label: "Dashboard", icon: FaTachometerAlt },
    {
      label: "Monitoring",
      icon: FaEye,
      submenu: [
        { path: "/anomalies", label: "Anomalies", icon: FaExclamationCircle },
        { path: "/threat-analysis", label: "Threat Analysis", icon: FaExclamationTriangle },
        { path: "/events", label: "Events", icon: FaListAlt },
        { path: "/packet-analysis", label: "PCAP Analysis", icon: FaDatabase },
        { path: "/honeypots", label: "Honeypots", icon: FaNetworkWired },
        { path: "/sentinel", label: "Sentinel", icon: FaShieldAlt },
      ]
    },
    {
      label: "Intelligence",
      icon: FaBrain,
      submenu: [
        { path: "/ml-insights", label: "ML Insights", icon: FaBrain },
        { path: "/topology", label: "Topology", icon: FaNetworkWired },
        { path: "/analytics", label: "Analytics", icon: FaChartBar },
        { path: "/advanced-dashboard", label: "Advanced NOC", icon: FaShieldAlt },
      ]
    },
    {
      label: "System",
      icon: FaCog,
      submenu: [
        { path: "/hunting", label: "Threat Hunting", icon: FaSearch },
        { path: "/admin", label: "Admin", icon: FaLock },
        { path: "/about", label: "About", icon: FaInfoCircle },
      ]
    }
  ];

  const isActive = (path) => {
    if (path === "/dashboard") {
      return location.pathname === "/" || location.pathname === "/dashboard";
    }
    return location.pathname.startsWith(path);
  };

  const isParentActive = (link) => {
    if (link.path) {
      return isActive(link.path);
    }
    if (link.submenu) {
      return link.submenu.some((sub) => isActive(sub.path));
    }
    return false;
  };

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const isLoginPage = location.pathname === "/login";

  return (
    <nav className="navbar-premium">
      <div className="navbar-inner">
        {/* Logo */}
        <Link to="/" className="navbar-logo">
          <div className="logo-icon">
            <FaShieldAlt />
          </div>
          <span className="logo-text">PhantomNet</span>
        </Link>

        {/* Navigation Links - Hidden on login page */}
        {!isLoginPage && isAuthenticated && (
          <div className="navbar-links">
            {navLinks.map((link) => {
              const Icon = link.icon;
              if (link.submenu) {
                return (
                  <div key={link.label} className="nav-item-dropdown">
                    <button
                      type="button"
                      className={`nav-link dropdown-trigger ${isParentActive(link) ? "active" : ""}`}
                      aria-haspopup="true"
                    >
                      <Icon className="nav-icon" />
                      <span>{link.label}</span>
                      <FaChevronDown className="dropdown-arrow" />
                    </button>
                    <div className="submenu-dropdown">
                      {link.submenu.map((sub) => {
                        const SubIcon = sub.icon;
                        return (
                          <Link
                            key={sub.path}
                            to={sub.path}
                            className={`submenu-link ${isActive(sub.path) ? "active" : ""}`}
                          >
                            <SubIcon className="submenu-icon" />
                            <span>{sub.label}</span>
                            {sub.path === "/sentinel" && pendingCount > 0 && (
                              <span className="sentinel-nav-badge">{pendingCount}</span>
                            )}
                          </Link>
                        );
                      })}
                    </div>
                  </div>
                );
              }
              return (
                <Link
                  key={link.path}
                  to={link.path}
                  className={`nav-link ${isActive(link.path) ? "active" : ""}`}
                >
                  <Icon className="nav-icon" />
                  <span>{link.label}</span>
                </Link>
              );
            })}
          </div>
        )}

        {/* Right Controls: Theme Toggle + User Badge + Logout */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <ThemeToggle />
          {!isLoginPage && isAuthenticated && (
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginLeft: "6px" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  fontSize: "12px",
                  fontWeight: 600,
                  color: "#22d3ee",
                  background: "rgba(34, 211, 238, 0.08)",
                  border: "1px solid rgba(34, 211, 238, 0.2)",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                }}
                title={`Logged in as ${user?.username} (${user?.role || 'Operator'})`}
              >
                <FaUserShield size={14} />
                <span>{user?.username || "OPERATOR"}</span>
              </div>
              <button
                onClick={handleLogout}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  background: "rgba(239, 68, 68, 0.1)",
                  border: "1px solid rgba(239, 68, 68, 0.25)",
                  color: "#ef4444",
                  padding: "6px 10px",
                  borderRadius: "6px",
                  fontSize: "12px",
                  fontWeight: 600,
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                }}
                title="Logout from PhantomNet"
              >
                <FaSignOutAlt size={12} />
                <span>LOGOUT</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;