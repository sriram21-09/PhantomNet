import React from "react";
import { Navigate, useLocation, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { Shield, ShieldAlert, ArrowLeft } from "lucide-react";

const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user, isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "80vh",
          gap: "1.25rem",
          color: "var(--accent-blue, #00d2ff)",
          fontFamily: "var(--font-heading, monospace)",
        }}
      >
        <div
          style={{
            position: "relative",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Shield size={48} className="animate-pulse" style={{ color: "#00d2ff" }} />
        </div>
        <div style={{ letterSpacing: "2px", fontSize: "0.9rem", opacity: 0.85 }}>
          AUTHENTICATING PHANTOMNET SECURE SESSION...
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && allowedRoles.length > 0) {
    const userRole = user?.role;
    if (!userRole || !allowedRoles.includes(userRole)) {
      return (
        <div
          className="access-denied-container"
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: "75vh",
            gap: "1.25rem",
            color: "var(--text-main, #f8fafc)",
            textAlign: "center",
            padding: "2rem",
          }}
        >
          <div
            style={{
              padding: "1rem",
              borderRadius: "50%",
              background: "rgba(239, 68, 68, 0.1)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "#ef4444",
            }}
          >
            <ShieldAlert size={48} />
          </div>
          <h2 style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f87171", margin: 0 }}>
            Access Denied
          </h2>
          <p style={{ maxWidth: "480px", color: "var(--text-muted, #94a3b8)", margin: 0, fontSize: "0.95rem", lineHeight: 1.6 }}>
            Your authenticated account (<strong>{user?.username || "unknown"}</strong>) with role <strong>{userRole || "Unknown"}</strong> does not have permission to access this module.
            <br />
            Required role: <strong>{allowedRoles.join(" or ")}</strong>.
          </p>
          <Link
            to="/dashboard"
            style={{
              marginTop: "0.75rem",
              display: "inline-flex",
              alignItems: "center",
              gap: "0.5rem",
              padding: "0.6rem 1.25rem",
              background: "var(--accent-blue, #00d2ff)",
              color: "#0f172a",
              fontWeight: 600,
              borderRadius: "6px",
              textDecoration: "none",
              fontSize: "0.875rem",
            }}
          >
            <ArrowLeft size={16} />
            Return to Dashboard
          </Link>
        </div>
      );
    }
  }

  return children;
};

export default ProtectedRoute;
