/**
 * Safely format and escape a single value for an RFC 4180 compliant CSV cell.
 * Handles null/undefined, commas, double quotes, and newlines.
 */
export const escapeCSVCell = (val) => {
    if (val === null || val === undefined) {
        return "";
    }
    const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
    if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
};

export const exportToCSV = (data, title = "PhantomNet_Report") => {
    if (!data) return "";
    let csvLines = [];

    if (Array.isArray(data)) {
        // Flat array of event objects (used by ThreatHunting and event tables)
        if (data.length > 0) {
            const headerSet = new Set();
            data.forEach(row => {
                if (row && typeof row === 'object') {
                    Object.keys(row).forEach(k => headerSet.add(k));
                }
            });
            const headers = Array.from(headerSet);
            if (headers.length > 0) {
                csvLines.push(headers.map(h => escapeCSVCell(h)).join(","));
                data.forEach(row => {
                    if (row && typeof row === 'object') {
                        const line = headers.map(h => escapeCSVCell(row[h])).join(",");
                        csvLines.push(line);
                    }
                });
            }
        }
    } else if (typeof data === 'object' && data.sections) {
        // Structured report with metadata and sections (used by ReportBuilder)
        csvLines.push(`Report Title,${escapeCSVCell(data.title || title)}`);
        csvLines.push(`Generated At,${escapeCSVCell(data.generated_at || new Date().toISOString())}`);
        csvLines.push("");

        Object.entries(data.sections).forEach(([sectionName, sectionData]) => {
            csvLines.push(escapeCSVCell(sectionName.toUpperCase()));

            if (typeof sectionData === 'object' && !Array.isArray(sectionData) && sectionData !== null) {
                Object.entries(sectionData).forEach(([key, value]) => {
                    const val = typeof value === 'object' && value !== null ? JSON.stringify(value).replace(/,/g, ';') : value;
                    csvLines.push(`${escapeCSVCell(key)},${escapeCSVCell(val)}`);
                });
            } else if (Array.isArray(sectionData)) {
                if (sectionData.length > 0) {
                    const headers = Object.keys(sectionData[0]);
                    csvLines.push(headers.map(h => escapeCSVCell(h)).join(","));
                    sectionData.forEach(item => {
                        csvLines.push(headers.map(h => escapeCSVCell(item[h])).join(","));
                    });
                }
            }
            csvLines.push("");
        });
    } else if (data && typeof data === 'object') {
        const headers = Object.keys(data);
        if (headers.length > 0) {
            csvLines.push(headers.map(h => escapeCSVCell(h)).join(","));
            csvLines.push(headers.map(h => escapeCSVCell(data[h])).join(","));
        }
    }

    const csvContent = csvLines.join("\r\n");

    if (typeof document !== "undefined") {
        const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.setAttribute("href", url);
        link.setAttribute("download", `${title.replace(/\s+/g, '_')}_${Date.now()}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    return csvContent;
};

export const exportToJSON = (data, title = "PhantomNet_Report") => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
    if (typeof document !== "undefined") {
        const link = document.createElement("a");
        link.setAttribute("href", dataStr);
        link.setAttribute("download", `${title.replace(/\s+/g, '_')}_${Date.now()}.json`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
    return dataStr;
};
