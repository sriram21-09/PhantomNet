import React, { useState, useEffect, useCallback } from "react";
import {
  FaCheckCircle,
  FaTimesCircle,
  FaExclamationTriangle,
  FaInfoCircle,
  FaTimes,
} from "react-icons/fa";
import "../../Styles/components/ToastNotification.css";

/**
 * Single toast item renderer.
 */
const ToastItem = ({ toast, onDismiss }) => {
  const [exiting, setExiting] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setExiting(true);
      setTimeout(() => onDismiss(toast.id), 350);
    }, toast.duration || 5000);
    return () => clearTimeout(timer);
  }, [toast.id, toast.duration, onDismiss]);

  const handleClose = () => {
    setExiting(true);
    setTimeout(() => onDismiss(toast.id), 350);
  };

  const ICONS = {
    success: <FaCheckCircle className="toast-notif-icon" />,
    error: <FaTimesCircle className="toast-notif-icon" />,
    warning: <FaExclamationTriangle className="toast-notif-icon" />,
    info: <FaInfoCircle className="toast-notif-icon" />,
  };

  return (
    <div
      className={`toast-notif toast-${toast.type} ${exiting ? "toast-exit" : "toast-enter"}`}
      role="alert"
      aria-live="assertive"
    >
      <div className="toast-notif-glow"></div>
      <div className="toast-notif-content">
        {ICONS[toast.type] || ICONS.info}
        <div className="toast-notif-body">
          {toast.title && <strong className="toast-notif-title">{toast.title}</strong>}
          <span className="toast-notif-message">{toast.message}</span>
        </div>
        <button
          className="toast-notif-close"
          onClick={handleClose}
          aria-label="Dismiss notification"
        >
          <FaTimes />
        </button>
      </div>
      <div className="toast-notif-progress">
        <div
          className="toast-notif-progress-bar"
          style={{ animationDuration: `${toast.duration || 5000}ms` }}
        />
      </div>
    </div>
  );
};

/**
 * ToastContainer — renders a stack of toast notifications.
 *
 * Usage:
 *   const { toasts, addToast, removeToast } = useToast();
 *   addToast({ type: "error", title: "API Error", message: "..." });
 *
 *   <ToastContainer toasts={toasts} onDismiss={removeToast} />
 */
const ToastContainer = ({ toasts = [], onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div className="toast-notif-container" aria-label="Notifications">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
      ))}
    </div>
  );
};

/**
 * useToast — custom hook for managing toast state.
 *
 * Returns { toasts, addToast, removeToast, clearAll }
 */
let toastIdCounter = 0;
export const useToast = () => {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((toast) => {
    const id = ++toastIdCounter;
    setToasts((prev) => [...prev, { ...toast, id }]);
    return id;
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setToasts([]);
  }, []);

  return { toasts, addToast, removeToast, clearAll };
};

export default ToastContainer;
