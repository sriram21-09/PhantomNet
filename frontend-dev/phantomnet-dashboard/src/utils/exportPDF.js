import { jsPDF } from "jspdf";
import "jspdf-autotable";

export const generatePDF = (reportData) => {
  const doc = new jsPDF();
  const title = reportData.title || "Threat Hunting Report";
  const timestamp = reportData.timestamp || new Date().toLocaleString();

  // Branding & Header
  doc.setFontSize(22);
  doc.setTextColor(0, 180, 216); // Deep Cyan
  doc.text("PHANTOMNET INTELLIGENCE", 105, 20, { align: "center" });

  doc.setFontSize(14);
  doc.setTextColor(100, 100, 100);
  doc.text(title, 105, 30, { align: "center" });

  doc.setFontSize(10);
  doc.text(`Generated: ${timestamp}`, 105, 38, { align: "center" });
  doc.text(reportData.description || "", 105, 43, { align: "center" });

  let currentY = 55;

  // Sections
  reportData.sections.forEach((section) => {
    // Check if we need a new page
    if (currentY > 260) {
      doc.addPage();
      currentY = 20;
    }

    // Section Title
    doc.setFontSize(15);
    doc.setTextColor(0, 119, 182);
    doc.text(section.title.toUpperCase(), 14, currentY);
    currentY += 8;

    if (section.type === 'table') {
      doc.autoTable({
        startY: currentY,
        head: [section.headers],
        body: section.rows,
        theme: 'grid',
        headStyles: { fillColor: [0, 77, 153], textColor: [255, 255, 255] },
        styles: { fontSize: 8, cellPadding: 2 },
        margin: { left: 14, right: 14 }
      });
      currentY = doc.lastAutoTable.finalY + 15;
    } else {
      // Regular content
      doc.setFontSize(10);
      doc.setTextColor(60, 60, 60);
      const splitText = doc.splitTextToSize(section.content || "", 180);
      doc.text(splitText, 14, currentY);
      currentY += (splitText.length * 5) + 12;
    }
  });

  // Footer
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150);
    doc.text(`Page ${i} of ${pageCount}`, 105, 285, { align: "center" });
    doc.text("Restricted Intelligence Report - PhantomNet Active Defense", 14, 285);
  }

  doc.save(`${title.replace(/\s+/g, '_')}_${new Date().getTime()}.pdf`);
};

export const exportToPDF = (data, title = "PhantomNet Report") => {
  // Legacy support or alternative schema
  generatePDF({
    title: title,
    sections: Object.entries(data.sections).map(([key, val]) => ({
      title: key,
      content: typeof val === 'string' ? val : JSON.stringify(val)
    }))
  });
};
