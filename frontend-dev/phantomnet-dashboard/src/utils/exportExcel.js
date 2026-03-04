import * as XLSX from 'xlsx';

const sheetMapping = {
    "Executive Summary": "Executive Summary",
    "Attack Timeline": "Attack Timeline",
    "Geographic Distribution": "Geographic Distribution",
    "Top Attackers": "Top Attackers",
    "Attack Patterns": "Attack Patterns",
    "Event Logs": "Event Logs",
    "Recommendations": "Recommendations"
};

export const exportToExcel = (data, title = "PhantomNet_Report") => {
    const wb = XLSX.utils.book_new();

    // Create sheets for each section
    Object.entries(data.sections).forEach(([sectionName, sectionData]) => {
        let ws;
        const sheetTitle = sheetMapping[sectionName] || sectionName;

        if (typeof sectionData === 'object' && !Array.isArray(sectionData)) {
            const rows = Object.entries(sectionData).map(([key, value]) => ({
                Metric: key.replace(/_/g, ' '),
                Value: typeof value === 'object' ? JSON.stringify(value) : value
            }));
            ws = XLSX.utils.json_to_sheet(rows);
        } else if (Array.isArray(sectionData)) {
            ws = XLSX.utils.json_to_sheet(sectionData);
        }

        if (ws) {
            XLSX.utils.book_append_sheet(wb, ws, sheetTitle.substring(0, 31));
        }
    });

    // Add Summary sheet at the beginning
    const summaryData = [
        { Field: "Report Name", Value: data.title },
        { Field: "Generated At", Value: data.generated_at },
        { Field: "Applied Filters", Value: JSON.stringify(data.filters_applied) }
    ];
    const summaryWs = XLSX.utils.json_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(wb, summaryWs, "Summary Overview");

    // Move summary to first position
    wb.SheetNames = ["Summary Overview", ...wb.SheetNames.filter(n => n !== "Summary Overview")];

    XLSX.writeFile(wb, `${title.replace(/\s+/g, '_')}_${new Date().getTime()}.xlsx`);
};
