import React, { useState } from "react";
import { FaSort, FaSortUp, FaSortDown, FaShieldAlt, FaChevronLeft, FaChevronRight } from "react-icons/fa";
import { usePagination } from "../hooks/usePagination";

const initialAttackers = [
    { ip: "192.168.1.105", count: 1245, country: "USA", risk: "High" },
    { ip: "45.76.12.190", count: 890, country: "China", risk: "Medium" },
    { ip: "103.25.46.2", count: 560, country: "Russia", risk: "High" },
    { ip: "82.165.23.11", count: 430, country: "Germany", risk: "Low" },
    { ip: "172.217.16.14", count: 320, country: "USA", risk: "Medium" },
    { ip: "1.1.1.1", count: 210, country: "Australia", risk: "Low" },
    { ip: "185.12.34.56", count: 150, country: "France", risk: "High" },
    { ip: "91.23.45.67", count: 120, country: "UK", risk: "Medium" },
    { ip: "5.6.7.8", count: 80, country: "Japan", risk: "Low" },
    { ip: "123.123.123.123", count: 45, country: "Canada", risk: "High" },
    { ip: "10.0.0.1", count: 30, country: "Local", risk: "Low" },
    { ip: "172.16.0.5", count: 25, country: "Private", risk: "Medium" },
    { ip: "192.168.0.1", count: 10, country: "Router", risk: "Low" },
];

const TopAttackers = () => {
    const [attackers, setAttackers] = useState(initialAttackers);
    const [sortConfig, setSortConfig] = useState({ key: "count", direction: "desc" });

    const {
        currentPage,
        totalPages,
        paginatedData,
        nextPage,
        prevPage,
    } = usePagination(attackers, 10); // Updated to 10 per page as requested

    const maxCount = Math.max(...initialAttackers.map(a => a.count));

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
