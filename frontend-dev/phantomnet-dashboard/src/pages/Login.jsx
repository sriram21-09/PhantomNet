import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Shield, Lock, User, AlertCircle, ArrowRight } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import "../Styles/pages/Login.css";

const Login = () => {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  // If already authenticated, redirect
  const from = location.state?.from?.pathname || "/dashboard";
  if (isAuthenticated) {
    navigate(from, { replace: true });
    return null;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsSubmitting(true);

    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err.message || "Invalid credentials. Please verify your username and password.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="cyber-login-container">
      <div className="cyber-login-card">
        <div className="cyber-login-header">
          <div className="cyber-login-logo-wrap">
            <Shield size={32} />
          </div>
          <h1 className="cyber-login-title">PhantomNet</h1>
          <p className="cyber-login-subtitle">Secure Defense &amp; Incident Response</p>
        </div>

        <form onSubmit={handleSubmit} className="cyber-login-form">
          {error && (
            <div className="cyber-login-error">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          <div className="cyber-form-group">
            <label className="cyber-form-label" htmlFor="login-username">Operator ID / Username</label>
            <div className="cyber-input-wrapper">
              <User size={18} className="cyber-input-icon" />
              <input
                id="login-username"
                type="text"
                className="cyber-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                required
                autoComplete="username"
                autoFocus
              />
            </div>
          </div>

          <div className="cyber-form-group">
            <label className="cyber-form-label" htmlFor="login-password">Access Key / Password</label>
            <div className="cyber-input-wrapper">
              <Lock size={18} className="cyber-input-icon" />
              <input
                id="login-password"
                type="password"
                className="cyber-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                autoComplete="current-password"
              />
            </div>
          </div>

          <button
            type="submit"
            className="cyber-login-btn"
            disabled={isSubmitting}
            id="login-submit-btn"
          >
            {isSubmitting ? (
              <span>Authenticating...</span>
            ) : (
              <>
                <span>Access Command Center</span>
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        <div className="cyber-login-footer">
          AUTHORIZED OPERATORS ONLY • SESSIONS AUDITED
        </div>
      </div>
    </div>
  );
};

export default Login;
