import { NavLink } from "react-router-dom";

function Navbar() {
  return (
    <nav className="navbar">
      <div className="navbar-left">
        <div className="navbar-logo">PhantomNet</div>
        <div className="navbar-tagline">Honeypot monitoring dashboard</div>
      </div>

      <div className="navbar-links">
        <NavLink to="/dashboard">Dashboard</NavLink>
        <NavLink to="/events">Events</NavLink>
      </div>
    </nav>
  );
}

export default Navbar;