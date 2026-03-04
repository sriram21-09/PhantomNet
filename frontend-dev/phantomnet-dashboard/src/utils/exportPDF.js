import { jsPDF } from "jspdf";
import "jspdf-autotable";

export const exportToPDF = (data, title = "PhantomNet Report") => {
  const doc = new jsPDF();
  const timestamp = new Date().toLocaleString();

  // Branding & Header
  doc.setFontSize(22);
  doc.setTextColor(0, 255, 255); // Cyan
  doc.text("PHANTOMNET", 105, 20, { align: "center" });

  doc.setFontSize(14);
  doc.setTextColor(150, 150, 150);
  doc.text(title, 105, 30, { align: "center" });

  doc.setFontSize(10);
  doc.text(`Generated: ${timestamp}`, 105, 38, { align: "center" });

  let currentY = 50;

  // Sections
  Object.entries(data.sections).forEach(([sectionName, sectionData]) => {
    // Section Title
    doc.setFontSize(16);
    doc.setTextColor(0, 180, 216);
    doc.text(sectionName.replace(/_/g, ' ').toUpperCase(), 14, currentY);
    currentY += 10;

    if (typeof sectionData === 'object' && !Array.isArray(sectionData)) {
      // Key-Value Table
      const rows = Object.entries(sectionData).map(([key, value]) => {
        if (key === 'threat_distribution') {
          return [key.replace(/_/g, ' '), 'Chart Below'];
        }
        return [
          key.replace(/_/g, ' '),
          typeof value === 'object' ? JSON.stringify(value) : value
        ];
      });

      doc.autoTable({
        startY: currentY,
        head: [['Metric', 'Value']],
        body: rows,
        theme: 'grid',
        headStyles: { fillColor: [0, 119, 182] },
        styles: { fontSize: 10 }
      });
      currentY = doc.lastAutoTable.finalY + 10;

      // Draw Simple Bar Chart for threat_distribution if present
      if (sectionData.threat_distribution) {
        doc.setFontSize(12);
        doc.setTextColor(50, 50, 50);
        doc.text("Threat Distribution Chart:", 14, currentY);
        currentY += 10;

        const distribution = sectionData.threat_distribution;
        const keys = Object.keys(distribution);
        const maxVal = Math.max(...Object.values(distribution), 1);
        const barMaxHeight = 100;

        keys.forEach((key, index) => {
          const val = distribution[key];
          const barWidth = (val / maxVal) * barMaxHeight;

          // Set color based on threat level
          if (key === 'CRITICAL') doc.setFillColor(255, 0, 0);
          else if (key === 'HIGH') doc.setFillColor(255, 69, 0);
          else if (key === 'MEDIUM') doc.setFillColor(255, 165, 0);
          else doc.setFillColor(0, 128, 0);

          doc.rect(40, currentY - 5, barWidth, 6, 'F');
          doc.setFontSize(8);
          doc.text(`${key}: ${val}`, 14, currentY);
          currentY += 10;
        });
        currentY += 5;
      }
    } else if (Array.isArray(sectionData)) {
      // Full Table
      if (sectionData.length > 0) {
        const headers = Object.keys(sectionData[0]);
        const rows = sectionData.map(item => Object.values(item));

        doc.autoTable({
          startY: currentY,
          head: [headers.map(h => h.replace(/_/g, ' ').toUpperCase())],
          body: rows,
          theme: 'striped',
          headStyles: { fillColor: [0, 77, 153] },
          styles: { fontSize: 8 }
        });
        currentY = doc.lastAutoTable.finalY + 15;
      }
    }

    // Add new page if needed
    if (currentY > 250) {
      doc.addPage();
      currentY = 20;
    }
  });

  // Footer
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(100);
    doc.text(`Page ${i} of ${pageCount}`, 105, 285, { align: "center" });
    doc.text("PhantomNet Active Defense - Confidential", 14, 285);
  }

  doc.save(`${title.replace(/\s+/g, '_')}_${new Date().getTime()}.pdf`);
};
