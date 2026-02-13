import { Link, useLocation } from "react-router-dom";
import { useContext } from "react";
import ThemeToggle from "./ThemeToggle";
import {
  FaShieldAlt,
  FaTachometerAlt,
  FaExclamationTriangle,
  FaListAlt,
  FaInfoCircle,
} from "react-icons/fa";
import "../styles/components/Navbar.css";

const Navbar = () => {
  const location = useLocation();

  const navLinks = [
    { path: "/dashboard", label: "Dashboard", icon: FaTachometerAlt },
    { path: "/threat-analysis", label: "Threat Analysis", icon: FaExclamationTriangle },
    { path: "/events", label: "Events", icon: FaListAlt },
    { path: "/about", label: "About", icon: FaInfoCircle },
  ];

  const isActive = (path) => {
    if (path === "/dashboard") {
      return location.pathname === "/" || location.pathname === "/dashboard";
    }
    return location.pathname.startsWith(path);
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