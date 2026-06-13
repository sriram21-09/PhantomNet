import { Link, useLocation } from "react-router-dom";
import { useContext } from "react";
import ThemeToggle from "./ThemeToggle";
import {
  FaShieldAlt,
  FaTachometerAlt,
  FaExclamationTriangle,
  FaListAlt,
  FaInfoCircle,
  FaNetworkWired,
  FaGlobeAmericas,
  FaChartBar,
  FaSearch,
  FaDatabase,
  FaLock,
  FaBrain,
  FaExclamationCircle,
  FaCog,
  FaEye,
  FaChevronDown
} from "react-icons/fa";
import "../Styles/components/Navbar.css";

const Navbar = () => {
  const location = useLocation();

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
      ]
    },
    {
      label: "Intelligence",
      icon: FaBrain,
      submenu: [
        { path: "/ml-insights", label: "ML Insights", icon: FaBrain },
        { path: "/topology", label: "Topology", icon: FaNetworkWired },
        { path: "/geo-stats", label: "Geo Stats", icon: FaGlobeAmericas },
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

        {/* Navigation Links */}
        <div className="navbar-links">
          {navLinks.map((link) => {
            const Icon = link.icon;
            if (link.submenu) {
              return (
                <div key={link.label} className="nav-item-dropdown">
                  <div className={`nav-link dropdown-trigger ${isParentActive(link) ? "active" : ""}`}>
                    <Icon className="nav-icon" />
                    <span>{link.label}</span>
                    <FaChevronDown className="dropdown-arrow" />
                  </div>
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

        {/* Theme Toggle Component */}
        <ThemeToggle />
      </div>
    </nav>
  );
};

export default Navbar;