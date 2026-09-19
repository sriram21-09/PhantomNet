import React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { Shield } from "lucide-react";

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
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

  return children;
};

export default ProtectedRoute;
