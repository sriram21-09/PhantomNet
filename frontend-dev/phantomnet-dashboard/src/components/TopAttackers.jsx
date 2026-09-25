import React, { useState, useEffect } from "react";
import { FaSort, FaSortUp, FaSortDown, FaShieldAlt, FaChevronLeft, FaChevronRight } from "react-icons/fa";
import { usePagination } from "../hooks/usePagination";
import { fetchTopThreatVectors } from "../services/api";

const TopAttackers = () => {
    const [attackers, setAttackers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [sortConfig, setSortConfig] = useState({ key: "count", direction: "desc" });

    useEffect(() => {
        let mounted = true;
        const loadVectors = async () => {
            try {
                const data = await fetchTopThreatVectors(50);
                if (mounted && Array.isArray(data) && data.length > 0) {
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
    }, []);

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
                <h3 className="panel-title">
                    <div className="title-icon reputation"><FaShieldAlt /></div>
                    Top Threat Vectors
                </h3>
                <div className="pagination-controls">
                    <span className="page-info">Page {currentPage} of {totalPages}</span>
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
                            disabled={currentPage === totalPages}
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
                                Source Identity {getSortIcon("ip")}
                            </th>
                            <th onClick={() => sortData("count")}>
                                Intensity {getSortIcon("count")}
                            </th>
                            <th onClick={() => sortData("country")}>
                                Origin {getSortIcon("country")}
                            </th>
                            <th onClick={() => sortData("risk")}>
                                Reputation {getSortIcon("risk")}
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {paginatedData.map((attacker, index) => (
                            <tr key={index}>
                                <td className="font-mono ip-column">
                                    {attacker.ip}
                                    <div className="ip-reputation-dot" title="Known Malicious"></div>
                                </td>
                                <td className="intensity-column">
                                    <div className="intensity-container">
                                        <span className="count-label">{attacker.count.toLocaleString()}</span>
                                        <div className="intensity-track">
                                            <div
                                                className="intensity-fill"
                                                style={{ width: `${(attacker.count / maxCount) * 100}%` }}
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
                                    <span className={`reputation-badge ${attacker.risk.toLowerCase()}`}>
                                        {attacker.risk} Risk
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default TopAttackers;
