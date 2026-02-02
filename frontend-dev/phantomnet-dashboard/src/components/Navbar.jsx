import { Link } from "react-router-dom";
import { useContext } from "react";
import { ThemeContext } from "../context/ThemeContext";

const Navbar = () => {
  const { theme, toggleTheme } = useContext(ThemeContext);

  return (
    <nav className="navbar">
      {/* LEFT */}
      <div className="navbar-left">
        <h2 className="navbar-logo">PhantomNet</h2>
      </div>

      {/* RIGHT */}
      <div className="navbar-right">
        <Link to="/dashboard">Dashboard</Link>
        <Link to="/threat-analysis">Threat Analysis</Link>
        <Link to="/events">Events</Link>
        <Link to="/about">About</Link>

        <button className="theme-btn" onClick={toggleTheme}>
          {theme === "light" ? "Dark" : "Light"}
        </button>
      </div>
    </nav>
  );
};

export default Navbar;