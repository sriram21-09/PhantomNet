import React, { useContext } from "react";
import { FaMoon, FaSun } from "react-icons/fa";
import { ThemeContext } from "../context/ThemeContext";
import "../styles/components/Navbar.css"; // Reuse existing styles for now

const ThemeToggle = () => {
  const { theme, toggleTheme } = useContext(ThemeContext);

  return (
    <div className={`theme-toggle-pro ${theme}`} onClick={toggleTheme} title={`Switch to ${theme === 'light' ? 'dark' : 'dark'} mode`}>
      <div className="toggle-track">
        <div className="toggle-thumb">
          {theme === "light" ? <FaMoon className="icon-moon" /> : <FaSun className="icon-sun" />}
        </div>
      </div>
      <span className="toggle-label">{theme === "light" ? "Dark Mode" : "Light Mode"}</span>
    </div>
  );
};

export default ThemeToggle;
