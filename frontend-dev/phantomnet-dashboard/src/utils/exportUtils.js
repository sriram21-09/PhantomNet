export const exportToCSV = (data, title = "PhantomNet_Report") => {
    let csvContent = "data:text/csv;charset=utf-8,";

    // Summary
    csvContent += `Report Title,${data.title}\n`;
    csvContent += `Generated At,${data.generated_at}\n\n`;

    Object.entries(data.sections).forEach(([sectionName, sectionData]) => {
        csvContent += `${sectionName.toUpperCase()}\n`;

        if (typeof sectionData === 'object' && !Array.isArray(sectionData)) {
            Object.entries(sectionData).forEach(([key, value]) => {
                const val = typeof value === 'object' ? JSON.stringify(value).replace(/,/g, ';') : value;
                csvContent += `${key},${val}\n`;
            });
        } else if (Array.isArray(sectionData)) {
            if (sectionData.length > 0) {
                const headers = Object.keys(sectionData[0]);
                csvContent += `${headers.join(",")}\n`;
                sectionData.forEach(item => {
                    csvContent += `${Object.values(item).join(",")}\n`;
                });
            }
        }
        csvContent += "\n";
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `${title.replace(/\s+/g, '_')}_${new Date().getTime()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
};

export const exportToJSON = (data, title = "PhantomNet_Report") => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", dataStr);
    link.setAttribute("download", `${title.replace(/\s+/g, '_')}_${new Date().getTime()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
};
