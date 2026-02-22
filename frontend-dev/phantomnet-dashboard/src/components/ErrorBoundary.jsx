import React from "react";
import { FaExclamationTriangle, FaRedo } from "react-icons/fa";
import "../styles/components/ErrorBoundary.css";

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true };
    }

    componentDidCatch(error, errorInfo) {
        console.error("Dashboard Error:", error, errorInfo);
    }

    handleRetry = () => {
        this.setState({ hasError: false });
        window.location.reload();
    };

    render() {
        if (this.state.hasError) {
            return (
                <div className="error-boundary-overlay">
                    <div className="error-card pro-card">
                        <div className="glitch-wrapper">
                            <FaExclamationTriangle className="error-icon" />
                            <h2 className="glitch-text" data-text="SYSTEM DEGRADED">SYSTEM DEGRADED</h2>
                        </div>
                        <p>A critical anomaly has compromised the command center interface. Security protocols have stablized the core.</p>
                        <button className="retry-btn" onClick={this.handleRetry}>
                            <FaRedo /> Re-establish Link
                        </button>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
