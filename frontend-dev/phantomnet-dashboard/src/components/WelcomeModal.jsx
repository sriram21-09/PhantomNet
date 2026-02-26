import React, { useState, useEffect } from "react";
import { FaRocket, FaShieldAlt, FaChartLine, FaCheckCircle } from "react-icons/fa";
import "../styles/components/WelcomeModal.css";

const WelcomeModal = () => {
    const [isVisible, setIsVisible] = useState(false);

    useEffect(() => {
        const hasSeenWelcome = localStorage.getItem("phantomnet_welcome_seen");
        if (!hasSeenWelcome) {
            setIsVisible(true);
        }
    }, []);

    const handleClose = () => {
        localStorage.setItem("phantomnet_welcome_seen", "true");
        setIsVisible(false);
    };

    if (!isVisible) return null;

    return (
        <div className="welcome-modal-overlay">
            <div className="welcome-modal-content pro-card">
                <div className="welcome-header">
                    <div className="welcome-icon-ring">
                        <FaRocket className="welcome-main-icon" />
                    </div>
                </div>

                <div className="welcome-body">
                    <h1>Welcome to PhantomNet</h1>
                    <p className="welcome-subtitle">Advanced Command Center for AI-Powered Threat Defense</p>

                    <div className="welcome-features">
                        <div className="welcome-feature-item">
                            <div className="feature-icon"><FaShieldAlt /></div>
                            <div className="feature-text">
                                <h3>Real-time Monitoring</h3>
                                <p>Live attack timeline and protocol distribution HUD.</p>
                            </div>
                        </div>

                        <div className="welcome-feature-item">
                            <div className="feature-icon"><FaChartLine /></div>
                            <div className="feature-text">
                                <h3>Threat Analytics</h3>
                                <p>Machine learning anomaly detection and risk scoring.</p>
                            </div>
                        </div>

                        <div className="welcome-feature-item">
                            <div className="feature-icon"><FaCheckCircle /></div>
                            <div className="feature-text">
                                <h3>Pro Environment</h3>
                                <p>Highly optimized, clean UI with low-latency data feeds.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="welcome-footer">
                    <button className="welcome-btn" onClick={handleClose}>
                        Establish Connection
                    </button>
                    <p className="footer-note">Connection Secured • SSL/TSL Active</p>
                </div>
            </div>
        </div>
    );
};

export default WelcomeModal;
