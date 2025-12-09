import { Link, useLocation } from "react-router-dom";

function Navbar() {
  const location = useLocation();

  return (
    <nav className="navbar">
      <div className="navbar-logo">PhantomNet</div>

      <div className="navbar-links">
        <Link
          to="/dashboard"
          className={location.pathname === "/dashboard" ? "active" : ""}
        >
          Dashboard
        </Link>

        <Link
          to="/events"
          className={location.pathname === "/events" ? "active" : ""}
        >
          Events
        </Link>
      </div>
    </nav>
  );
}

export default Navbar;