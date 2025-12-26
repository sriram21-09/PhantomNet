import { Link } from "react-router-dom";
import { useContext } from "react";
import { ThemeContext } from "../context/ThemeContext";

const Navbar = () => {
  const { theme, toggleTheme } = useContext(ThemeContext);

  return (
    <nav style={styles.nav}>
      <h2 style={styles.logo}>PhantomNet</h2>

      <div>
        <Link style={styles.link} to="/dashboard">
          Dashboard
        </Link>
        <Link style={styles.link} to="/events">
          Events
        </Link>
        <Link style={styles.link} to="/about">
          About
        </Link>

        <button
          onClick={toggleTheme}
          style={styles.button}
          aria-label="Toggle theme"
        >
          {theme === "light" ? "Dark" : "Light"}
        </button>
      </div>
    </nav>
  );
};

const styles = {
  nav: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "15px 30px",
    background: "#1e3a8a",
    color: "white"
  },
  logo: {
    margin: 0
  },
  link: {
    color: "white",
    marginLeft: "20px",
    textDecoration: "none",
    fontWeight: "bold"
  },
  button: {
    marginLeft: "20px",
    padding: "6px 12px",
    cursor: "pointer",
    borderRadius: "4px",
    border: "none"
  }
};

export default Navbar;