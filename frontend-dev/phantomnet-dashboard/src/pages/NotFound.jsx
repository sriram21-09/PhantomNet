import React from "react";
import { Link } from "react-router-dom";
import { ShieldAlert, ArrowLeft, Home } from "lucide-react";

const NotFound = () => {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        minHeight: "calc(100vh - 120px)",
        textAlign: "center",
        padding: "40px 20px",
      }}
    >
      <div
        style={{
          background: "rgba(239, 68, 68, 0.1)",
          border: "1px solid rgba(239, 68, 68, 0.3)",
          borderRadius: "50%",
          padding: "24px",
          marginBottom: "24px",
          boxShadow: "0 0 30px rgba(239, 68, 68, 0.2)",
        }}
      >
        <ShieldAlert size={64} color="#ef4444" />
      </div>

      <h1
        style={{
          fontSize: "4rem",
          fontWeight: 900,
          margin: "0 0 8px 0",
          letterSpacing: "2px",
          color: "#ef4444",
          fontFamily: "monospace",
        }}
      >
        404
      </h1>

      <h2
        style={{
          fontSize: "1.5rem",
          fontWeight: 700,
          marginBottom: "16px",
          letterSpacing: "1px",
        }}
      >
        SECTOR UNREACHABLE // ROUTE NOT FOUND
      </h2>

      <p
        style={{
          maxWidth: "480px",
          fontSize: "0.95rem",
          color: "#94a3b8",
          lineHeight: "1.6",
          marginBottom: "32px",
        }}
      >
        The requested endpoint or sector does not exist on the PhantomNet defense perimeter.
        Verify the URL coordinates or return to mission control.
      </p>

      <div style={{ display: "flex", gap: "16px" }}>
        <Link
          to="/"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            padding: "12px 24px",
            background: "linear-gradient(135deg, #3b82f6, #1d4ed8)",
            color: "#ffffff",
            borderRadius: "8px",
            textDecoration: "none",
            fontWeight: 600,
            fontSize: "0.9rem",
            boxShadow: "0 4px 14px rgba(59, 130, 246, 0.4)",
            transition: "transform 0.2s, box-shadow 0.2s",
          }}
        >
          <Home size={18} />
          Return to Dashboard
        </Link>
      </div>
    </div>
  );
};

export default NotFound;
