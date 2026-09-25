import React, { useState, useEffect } from "react";
import { FaSort, FaSortUp, FaSortDown, FaShieldAlt, FaChevronLeft, FaChevronRight } from "react-icons/fa";
import { usePagination } from "../hooks/usePagination";
import { fetchTopThreatVectors } from "../services/api";

const TopAttackers = ({ mode = "all" }) => {
    const [attackers, setAttackers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [sortConfig, setSortConfig] = useState({ key: "count", direction: "desc" });

    useEffect(() => {
        let mounted = true;
        const loadVectors = async () => {
            try {
                const data = await fetchTopThreatVectors(50, mode);
                if (mounted && Array.isArray(data)) {
                    setAttackers(data);
                }
            } catch (err) {
                console.warn("[TopAttackers] Failed to fetch top threat vectors:", err);
            } finally {
                if (mounted) setLoading(false);
            }
        };

        loadVectors();
        const interval = setInterval(loadVectors, 10000);
        return () => {
            mounted = false;
            clearInterval(interval);
        };
    }, [mode]);

    const {
        currentPage,
        totalPages,
        paginatedData,
        nextPage,
        prevPage,
    } = usePagination(attackers, 10);

    const maxCount = attackers.length > 0 ? Math.max(...attackers.map(a => a.count), 1) : 1;

    const sortData = (key) => {
        let direction = "desc";
        if (sortConfig.key === key && sortConfig.direction === "desc") {
            direction = "asc";
        }

        const sortedData = [...attackers].sort((a, b) => {
            if (a[key] < b[key]) return direction === "asc" ? -1 : 1;
            if (a[key] > b[key]) return direction === "asc" ? 1 : -1;
            return 0;
        });

        setSortConfig({ key, direction });
        setAttackers(sortedData);
    };

    const getSortIcon = (key) => {
        if (sortConfig.key !== key) return <FaSort className="sort-icon-inactive" />;
        return sortConfig.direction === "asc" ? <FaSortUp className="sort-icon-active" /> : <FaSortDown className="sort-icon-active" />;
    };

    return (
        <div className="top-attackers-card pro-card">
            <div className="card-header">
                <div>
                    <h3 className="panel-title">
                        <div className="title-icon reputation"><FaShieldAlt /></div>
                        Top Source Vectors
                    </h3>
                    <p className="panel-subtitle" style={{ fontSize: "11px", color: "var(--text-dim, #64748b)", margin: "2px 0 0 28px" }}>
                        Observed traffic categorized by origin type (Docker Bridge, RFC 5737 Benchmark, External)
                    </p>
                </div>
                <div className="pagination-controls">
                    <span className="page-info">Page {currentPage} of {totalPages || 1}</span>
                    <div className="pagination-buttons">
                        <button
                            className="pagination-btn"
                            onClick={prevPage}
                            disabled={currentPage === 1}
                        >
                            <FaChevronLeft />
                        </button>
                        <button
                            className="pagination-btn"
                            onClick={nextPage}
                            disabled={currentPage >= totalPages}
                        >
                            <FaChevronRight />
                        </button>
                    </div>
                </div>
            </div>
            <div className="table-container">
                <table className="premium-table pro-table">
                    <thead>
                        <tr>
                            <th onClick={() => sortData("ip")}>
                                Source IP {getSortIcon("ip")}
                            </th>
                            <th>
                                Source Classification
                            </th>
                            <th onClick={() => sortData("count")}>
                                Frequency / Intensity {getSortIcon("count")}
                            </th>
                            <th onClick={() => sortData("country")}>
                                Network Origin {getSortIcon("country")}
                            </th>
                            <th onClick={() => sortData("risk")}>
                                Assessment {getSortIcon("risk")}
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {paginatedData.length === 0 && !loading && (
                            <tr>
                                <td colSpan="5" style={{ textAlign: "center", padding: "20px", color: "#64748b" }}>
                                    No source vectors detected for the selected mode.
                                </td>
                            </tr>
                        )}
                        {paginatedData.map((attacker, index) => {
                            const isBridge = attacker.source_category === "internal_bridge";
                            const isTestNet = attacker.source_category === "testnet" || attacker.is_synthetic;
                            
                            return (
                                <tr key={index}>
                                    <td className="font-mono ip-column">
                                        {attacker.ip}
                                        <div 
                                            className="ip-reputation-dot" 
                                            style={{ 
                                                backgroundColor: isBridge ? "#f59e0b" : isTestNet ? "#8b5cf6" : "#ef4444" 
                                            }}
                                            title={attacker.source_type}
                                        />
                                    </td>
                                    <td>
                                        <span 
                                            className={`source-type-badge ${isBridge ? "badge-bridge" : isTestNet ? "badge-testnet" : "badge-external"}`}
                                            style={{
                                                fontSize: "11px",
                                                fontWeight: 600,
                                                padding: "3px 8px",
                                                borderRadius: "6px",
                                                display: "inline-block",
                                                backgroundColor: isBridge ? "rgba(245, 158, 11, 0.12)" : isTestNet ? "rgba(139, 92, 246, 0.12)" : "rgba(239, 68, 68, 0.12)",
                                                color: isBridge ? "#f59e0b" : isTestNet ? "#a78bfa" : "#f87171",
                                                border: `1px solid ${isBridge ? "rgba(245, 158, 11, 0.3)" : isTestNet ? "rgba(139, 92, 246, 0.3)" : "rgba(239, 68, 68, 0.3)"}`,
                                            }}
                                        >
                                            {attacker.source_type || (isBridge ? "Docker Bridge" : isTestNet ? "Test / Benchmark" : "External Source")}
                                        </span>
                                    </td>
                                    <td className="intensity-column">
                                        <div className="intensity-container">
                                            <span className="count-label">
                                                {attacker.count.toLocaleString()}
                                                {attacker.percentage ? ` (${attacker.percentage}%)` : ""}
                                            </span>
                                            <div className="intensity-track">
                                                <div
                                                    className="intensity-fill"
                                                    style={{ 
                                                        width: `${(attacker.count / maxCount) * 100}%`,
                                                        backgroundColor: isBridge ? "#f59e0b" : isTestNet ? "#8b5cf6" : "#3b82f6",
                                                    }}
                                                ></div>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <div className="origin-cell">
                                            <span className="country-label">{attacker.country}</span>
                                        </div>
                                    </td>
                                    <td>
                                        <span className={`reputation-badge ${(attacker.risk || "low").toLowerCase()}`}>
                                            {isTestNet ? "Benchmark" : `${attacker.risk} Risk`}
                                        </span>
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default TopAttackers;
