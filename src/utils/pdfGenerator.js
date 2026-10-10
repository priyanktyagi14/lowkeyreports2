import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import { formatExactCurrency } from "../data/telemetryData";

const primaryColor = [18, 22, 28]; // Dark Charcoal
const accentBorder = [50, 60, 75];
const severeRed = [180, 40, 40];
const mediumAmber = [185, 120, 20];
const ignorableGray = [100, 110, 120];

/**
 * Draws professional header on each page
 */
function drawPageHeader(doc, title, subtitle, companyName) {
  doc.setFillColor(...primaryColor);
  doc.rect(14, 12, 182, 3, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(7.5);
  doc.setTextColor(110, 120, 135);
  doc.text(`CONFIDENTIAL // BOARD OF DIRECTORS BRIEFING — ${companyName.toUpperCase()}`, 14, 20);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.setTextColor(...primaryColor);
  doc.text(title, 14, 27);

  if (subtitle) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(80, 90, 105);
    doc.text(subtitle, 14, 33);
  }

  doc.setFontSize(7.5);
  doc.setTextColor(120, 130, 140);
  const dateStr = new Date().toLocaleDateString("en-US", { year: 'numeric', month: 'long', day: 'numeric' });
  doc.text(`CRQ ENGINE: Local Laya AI Actuarial Core  |  FAIR (CRQ) STANDARD  |  AUDIT DATE: ${dateStr}`, 14, 39);

  doc.setDrawColor(...accentBorder);
  doc.setLineWidth(0.4);
  doc.line(14, 42, 196, 42);
}

/**
 * Adds running page footers to all pages in doc
 */
function addPageFooters(doc) {
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setDrawColor(210, 215, 225);
    doc.setLineWidth(0.3);
    doc.line(14, 283, 196, 283);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(120, 130, 140);
    doc.text(`CRQ Board Dossier  |  Actuarial Risk Framework  |  Strictly Confidential`, 14, 288);
    doc.text(`Page ${i} of ${pageCount}`, 178, 288);
  }
}

/**
 * Renders rich vulnerability cards with no truncation across dynamic pages
 */
function renderVulnerabilityCards(doc, items, startY = 48) {
  let currentY = startY;

  items.forEach((item) => {
    // Measure text heights
    const wrapWidth = 174;
    const techLines = doc.splitTextToSize(item.technicalFinding || "Telemetry anomaly detected.", wrapWidth);
    const busLines = doc.splitTextToSize(item.businessImpact || "Operational and financial risk exposure.", wrapWidth);
    const planLines = doc.splitTextToSize(item.solutionPlan || "Implement multi-phase remediation controls.", wrapWidth);

    // Calculate required height for card
    // Header (12) + Meta row (9) + Finding (techLines*3.8 + 6) + Impact (busLines*3.8 + 6) + Plan (planLines*3.8 + 6) + Compliance/ROI (8) + padding (8)
    const cardHeight = Math.max(
      52,
      28 + (techLines.length * 3.6) + (busLines.length * 3.6) + (planLines.length * 3.6) + 16
    );

    // Check if new page is needed
    if (currentY + cardHeight > 275) {
      doc.addPage();
      currentY = 20;
    }

    // Card background & border
    doc.setFillColor(248, 250, 252);
    doc.rect(14, currentY, 182, cardHeight, "F");
    doc.setDrawColor(215, 222, 232);
    doc.setLineWidth(0.3);
    doc.rect(14, currentY, 182, cardHeight, "S");

    // Severity indicator strip on left border
    if (item.severity === "Severe") doc.setFillColor(...severeRed);
    else if (item.severity === "Medium") doc.setFillColor(...mediumAmber);
    else doc.setFillColor(...ignorableGray);
    doc.rect(14, currentY, 2.5, cardHeight, "F");

    // Title line & ID
    let textY = currentY + 6;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(20, 25, 35);
    doc.text(`[${item.id}] ${item.name}`, 18, textY);

    // Severity & Probability Badge
    doc.setFontSize(7.5);
    if (item.severity === "Severe") doc.setTextColor(...severeRed);
    else if (item.severity === "Medium") doc.setTextColor(...mediumAmber);
    else doc.setTextColor(...ignorableGray);
    doc.text(`${item.severity.toUpperCase()} // ${item.annualProbability || '70% Probability'}`, 148, textY);

    // Meta row: Target Group | Source | Threat Actor | MITRE ATT&CK
    textY += 5.5;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.8);
    doc.setTextColor(90, 100, 115);
    const metaStr = `TARGET: ${item.targetGroup}  |  SOURCE: ${item.source}  |  VECTOR: ${item.attackVector || 'T1190'}`;
    doc.text(metaStr, 18, textY);

    // Financial Metrics Sub-banner
    textY += 5;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.setTextColor(180, 30, 30);
    doc.text(`EXPOSURE: ${formatExactCurrency(item.lossIfIgnored)}`, 18, textY);
    doc.setTextColor(30, 40, 50);
    doc.text(`FIX CAPITAL: ${formatExactCurrency(item.solutionCost)}`, 74, textY);
    doc.setTextColor(20, 110, 50);
    doc.text(`ROI DIRECTIVE: ${item.recommendation}`, 125, textY);

    // Technical Telemetry Evidence
    textY += 5.5;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(6.8);
    doc.setTextColor(60, 70, 85);
    doc.text("TECHNICAL FINDING & TELEMETRY EVIDENCE:", 18, textY);
    textY += 3.6;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.8);
    doc.setTextColor(40, 45, 55);
    doc.text(techLines, 18, textY);
    textY += (techLines.length * 3.6);

    // Business & Actuarial Impact
    doc.setFont("helvetica", "bold");
    doc.setFontSize(6.8);
    doc.setTextColor(150, 30, 30);
    doc.text("ACTUARIAL BUSINESS IMPACT & LOSS BREAKDOWN:", 18, textY);
    textY += 3.6;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.8);
    doc.setTextColor(45, 50, 60);
    doc.text(busLines, 18, textY);
    textY += (busLines.length * 3.6);

    // Phased Remediation Plan
    doc.setFont("helvetica", "bold");
    doc.setFontSize(6.8);
    doc.setTextColor(20, 100, 50);
    doc.text("ENGINEERING REMEDIATION ROADMAP:", 18, textY);
    textY += 3.6;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.8);
    doc.setTextColor(40, 45, 55);
    doc.text(planLines, 18, textY);
    textY += (planLines.length * 3.6);

    // Regulatory Compliance Footer within Card
    if (item.complianceImpact) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(6.3);
      doc.setTextColor(100, 105, 120);
      doc.text(`STATUTORY / COMPLIANCE SCOPE: ${item.complianceImpact}`, 18, textY + 1);
    }

    currentY += cardHeight + 5;
  });

  return currentY;
}

/**
 * Generates an in-depth category report (Internal, External, or Machines)
 */
export function generateCategoryReport(categoryKey, vulnerabilities, companyName = "Enterprise Global Corp") {
  const doc = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4"
  });

  const categoryTitles = {
    internal: {
      title: "INTERNAL PEOPLE RISK QUANTIFICATION DOSSIER",
      subtitle: "Employee Credential Hygiene, Developer Secrets & Insider Exposure",
      description: "Comprehensive financial exposure analysis translating developer repositories, IAM configurations, and employee workstation telemetry into defensible, board-level monetary decisions."
    },
    external: {
      title: "EXTERNAL ENTITIES RISK QUANTIFICATION DOSSIER",
      subtitle: "Customer Surface, Vendor Supply Chain & Third-Party Blast Radius",
      description: "Monetary risk quantification of customer-facing endpoints, API authentication boundaries, and third-party SaaS vendor integrations, evaluating material exposure under SEC and GDPR frameworks."
    },
    machines: {
      title: "MACHINES & INFRASTRUCTURE RISK QUANTIFICATION DOSSIER",
      subtitle: "Server Vulnerabilities, Cloud Bastions & Database Perimeter Threats",
      description: "Actuarial cyber valuation linking unpatched server CVEs, container ingress configurations, and database exposure to potential downtime, business interruption, and ransomware recovery loss."
    }
  };

  const info = categoryTitles[categoryKey] || {
    title: "CYBER RISK QUANTIFICATION REPORT",
    subtitle: "Consolidated Technical Risk Translation",
    description: "Executive valuation generated via Local Laya AI Actuarial Core."
  };

  const filtered = vulnerabilities.filter(v => v.category === categoryKey);
  const categoryLoss = filtered.reduce((sum, v) => sum + v.lossIfIgnored, 0);
  const actionableItems = filtered.filter(v => v.severity !== "Ignorable");
  const categoryCost = actionableItems.reduce((sum, v) => sum + v.solutionCost, 0);
  const categoryActionableLoss = actionableItems.reduce((sum, v) => sum + v.lossIfIgnored, 0);
  const netSavings = categoryActionableLoss - categoryCost;

  const severeCount = filtered.filter(v => v.severity === "Severe").length;
  const mediumCount = filtered.filter(v => v.severity === "Medium").length;
  const ignorableCount = filtered.filter(v => v.severity === "Ignorable").length;

  // ================= PAGE 1: EXECUTIVE BRIEFING & METRICS =================
  drawPageHeader(doc, info.title, info.subtitle, companyName);

  // Executive Description
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(40, 45, 55);
  const splitDesc = doc.splitTextToSize(info.description, 182);
  doc.text(splitDesc, 14, 50);

  // Financial Metrics Block (3 Key figures)
  const boxY = 60;
  const boxW = 58;
  const boxH = 26;

  // Box 1: Est. Loss
  doc.setFillColor(245, 246, 248);
  doc.rect(14, boxY, boxW, boxH, "F");
  doc.setDrawColor(210, 215, 225);
  doc.rect(14, boxY, boxW, boxH, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(100, 110, 125);
  doc.text("EST. POTENTIAL LOSS", 18, boxY + 7);
  doc.setFontSize(14);
  doc.setTextColor(180, 30, 30);
  doc.text(formatExactCurrency(categoryLoss), 18, boxY + 16);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(110, 115, 125);
  doc.text("Total unmitigated exposure", 18, boxY + 22);

  // Box 2: Fix Cost
  doc.setFillColor(245, 246, 248);
  doc.rect(76, boxY, boxW, boxH, "F");
  doc.setDrawColor(210, 215, 225);
  doc.rect(76, boxY, boxW, boxH, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(100, 110, 125);
  doc.text("EST. SOLUTION COST", 80, boxY + 7);
  doc.setFontSize(14);
  doc.setTextColor(30, 40, 50);
  doc.text(formatExactCurrency(categoryCost), 80, boxY + 16);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(110, 115, 125);
  doc.text("Targeted remediation capital", 80, boxY + 22);

  // Box 3: Net Saved
  doc.setFillColor(245, 246, 248);
  doc.rect(138, boxY, boxW, boxH, "F");
  doc.setDrawColor(210, 215, 225);
  doc.rect(138, boxY, boxW, boxH, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(100, 110, 125);
  doc.text("NET CAPITAL PRESERVED", 142, boxY + 7);
  doc.setFontSize(14);
  doc.setTextColor(20, 120, 60);
  doc.text(formatExactCurrency(netSavings), 142, boxY + 16);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(110, 115, 125);
  doc.text("Mitigation ROI advantage", 142, boxY + 22);

  // Severity Triage Strip
  const stripY = boxY + boxH + 6;
  doc.setFillColor(250, 251, 253);
  doc.rect(14, stripY, 182, 10, "F");
  doc.setDrawColor(220, 225, 235);
  doc.rect(14, stripY, 182, 10, "S");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(40, 50, 65);
  doc.text(`TRIAGE STATUS:`, 18, stripY + 6.5);
  doc.setTextColor(...severeRed);
  doc.text(`${severeCount} SEVERE`, 48, stripY + 6.5);
  doc.setTextColor(120, 130, 140);
  doc.text("|", 72, stripY + 6.5);
  doc.setTextColor(...mediumAmber);
  doc.text(`${mediumCount} MEDIUM`, 78, stripY + 6.5);
  doc.setTextColor(120, 130, 140);
  doc.text("|", 102, stripY + 6.5);
  doc.setTextColor(...ignorableGray);
  doc.text(`${ignorableCount} IGNORABLE (NEGATIVE ROI)`, 108, stripY + 6.5);

  // Table of Findings
  const tableData = filtered.map(item => [
    item.id,
    item.name,
    item.targetGroup,
    formatExactCurrency(item.lossIfIgnored),
    formatExactCurrency(item.solutionCost),
    item.severity.toUpperCase(),
    item.recommendation
  ]);

  autoTable(doc, {
    startY: stripY + 15,
    head: [["ID", "Vulnerability / Risk Vector", "Target Group", "Loss If Ignored", "Fix Cost", "Severity", "Recommendation"]],
    body: tableData,
    theme: "plain",
    styles: {
      fontSize: 7.5,
      cellPadding: 2.8,
      textColor: [40, 45, 50],
      lineColor: [225, 230, 238],
      lineWidth: 0.2
    },
    headStyles: {
      fillColor: [238, 241, 246],
      textColor: [30, 35, 45],
      fontStyle: "bold",
      lineWidth: 0.3,
      lineColor: [200, 208, 220]
    },
    columnStyles: {
      0: { cellWidth: 14, fontStyle: "bold" },
      1: { cellWidth: 50 },
      2: { cellWidth: 26 },
      3: { cellWidth: 24, fontStyle: "bold", textColor: [180, 30, 30] },
      4: { cellWidth: 18 },
      5: { cellWidth: 18, fontStyle: "bold" },
      6: { cellWidth: 32 }
    },
    didParseCell: function(data) {
      if (data.section === 'body' && data.column.index === 5) {
        if (data.cell.raw === "SEVERE") {
          data.cell.styles.textColor = severeRed;
        } else if (data.cell.raw === "MEDIUM") {
          data.cell.styles.textColor = mediumAmber;
        } else {
          data.cell.styles.textColor = ignorableGray;
        }
      }
    }
  });

  // ================= PAGES 2+: DEEP DIVE ACTUARIAL DOSSIER CARDS =================
  doc.addPage();
  drawPageHeader(doc, "ACTUARIAL RISK PROFILES & REMEDIATION ROADMAP", `Comprehensive Dossier for ${filtered.length} Findings`, companyName);

  renderVulnerabilityCards(doc, filtered, 48);

  addPageFooters(doc);

  const filename = `${categoryKey}_risk_quantification_dossier.pdf`;
  doc.save(filename);
}

/**
 * Generates an exhaustive Consolidated Master Executive Dossier across ALL 3 domains
 */
export function generateMasterReport(vulnerabilities, companyName = "Enterprise Global Corp") {
  const doc = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4"
  });

  const totalLoss = vulnerabilities.reduce((sum, v) => sum + v.lossIfIgnored, 0);
  const actionableItems = vulnerabilities.filter(v => v.severity !== "Ignorable");
  const totalCost = actionableItems.reduce((sum, v) => sum + v.solutionCost, 0);
  const actionableLoss = actionableItems.reduce((sum, v) => sum + v.lossIfIgnored, 0);
  const netSavings = actionableLoss - totalCost;

  const severeItems = vulnerabilities.filter(v => v.severity === "Severe");
  const mediumItems = vulnerabilities.filter(v => v.severity === "Medium");
  const ignorableItems = vulnerabilities.filter(v => v.severity === "Ignorable");

  // ================= COVER PAGE: BOARD EXECUTIVE MASTER BRIEFING =================
  drawPageHeader(
    doc,
    "ENTERPRISE CYBER RISK QUANTIFICATION MASTER DOSSIER",
    "Comprehensive Actuarial Exposure Valuation across Internal, External & Machine Assets",
    companyName
  );

  // Executive Narrative
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(40, 45, 55);
  const narrative = `This Master Cyber Risk Quantification Dossier translates enterprise technical telemetry from SIEM, EDR, and IAM environments into actuarially sound financial balance sheet exposure using the FAIR (Factor Analysis of Information Risk) framework. Rather than reacting blindly to every security signal, this report delivers high-leverage capital allocation decisions: prioritizing vulnerabilities with exponential remediation ROI while explicitly deprioritizing negative-ROI findings where mitigation cost exceeds probable financial loss.`;
  const splitNarrative = doc.splitTextToSize(narrative, 182);
  doc.text(splitNarrative, 14, 49);

  // 3 Primary Metric Callout Boxes
  const boxY = 66;
  const boxW = 58;
  const boxH = 26;

  // Box 1: Total Unmitigated Exposure
  doc.setFillColor(245, 246, 248);
  doc.rect(14, boxY, boxW, boxH, "F");
  doc.setDrawColor(210, 215, 225);
  doc.rect(14, boxY, boxW, boxH, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(100, 110, 125);
  doc.text("TOTAL UNMITIGATED EXPOSURE", 18, boxY + 7);
  doc.setFontSize(14);
  doc.setTextColor(180, 30, 30);
  doc.text(formatExactCurrency(totalLoss), 18, boxY + 16);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(110, 115, 125);
  doc.text("Enterprise financial blast radius", 18, boxY + 22);

  // Box 2: Total Remediation Spend
  doc.setFillColor(245, 246, 248);
  doc.rect(76, boxY, boxW, boxH, "F");
  doc.setDrawColor(210, 215, 225);
  doc.rect(76, boxY, boxW, boxH, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(100, 110, 125);
  doc.text("REQUIRED FIX CAPITAL", 80, boxY + 7);
  doc.setFontSize(14);
  doc.setTextColor(30, 40, 50);
  doc.text(formatExactCurrency(totalCost), 80, boxY + 16);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(110, 115, 125);
  doc.text("High-ROI remediation budget", 80, boxY + 22);

  // Box 3: Net Capital Preserved
  doc.setFillColor(245, 246, 248);
  doc.rect(138, boxY, boxW, boxH, "F");
  doc.setDrawColor(210, 215, 225);
  doc.rect(138, boxY, boxW, boxH, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(100, 110, 125);
  doc.text("NET CAPITAL PRESERVED", 142, boxY + 7);
  doc.setFontSize(14);
  doc.setTextColor(20, 120, 60);
  doc.text(formatExactCurrency(netSavings), 142, boxY + 16);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(110, 115, 125);
  doc.text("Preserved shareholder value", 142, boxY + 22);

  // Category Domain Comparison Table
  const internalItems = vulnerabilities.filter(v => v.category === "internal");
  const externalItems = vulnerabilities.filter(v => v.category === "external");
  const machineItems = vulnerabilities.filter(v => v.category === "machines");

  const domainTable = [
    [
      "Internal People & Devs",
      `${internalItems.length} Vectors`,
      formatExactCurrency(internalItems.reduce((s, v) => s + v.lossIfIgnored, 0)),
      formatExactCurrency(internalItems.filter(v => v.severity !== "Ignorable").reduce((s, v) => s + v.solutionCost, 0)),
      `${internalItems.filter(v => v.severity === "Severe").length} Severe, ${internalItems.filter(v => v.severity === "Medium").length} Med, ${internalItems.filter(v => v.severity === "Ignorable").length} Ign`
    ],
    [
      "External Customers & Vendors",
      `${externalItems.length} Vectors`,
      formatExactCurrency(externalItems.reduce((s, v) => s + v.lossIfIgnored, 0)),
      formatExactCurrency(externalItems.filter(v => v.severity !== "Ignorable").reduce((s, v) => s + v.solutionCost, 0)),
      `${externalItems.filter(v => v.severity === "Severe").length} Severe, ${externalItems.filter(v => v.severity === "Medium").length} Med, ${externalItems.filter(v => v.severity === "Ignorable").length} Ign`
    ],
    [
      "Machines & Cloud Infra",
      `${machineItems.length} Vectors`,
      formatExactCurrency(machineItems.reduce((s, v) => s + v.lossIfIgnored, 0)),
      formatExactCurrency(machineItems.filter(v => v.severity !== "Ignorable").reduce((s, v) => s + v.solutionCost, 0)),
      `${machineItems.filter(v => v.severity === "Severe").length} Severe, ${machineItems.filter(v => v.severity === "Medium").length} Med, ${machineItems.filter(v => v.severity === "Ignorable").length} Ign`
    ]
  ];

  autoTable(doc, {
    startY: boxY + boxH + 8,
    head: [["Risk Domain", "Findings", "Total Exposure", "Remediation Spend", "Triage Distribution"]],
    body: domainTable,
    theme: "plain",
    styles: { fontSize: 8, cellPadding: 3, textColor: [35, 40, 50], lineColor: [220, 225, 235], lineWidth: 0.2 },
    headStyles: { fillColor: [238, 242, 248], textColor: [25, 30, 40], fontStyle: "bold" },
    columnStyles: {
      0: { fontStyle: "bold", cellWidth: 45 },
      1: { cellWidth: 24 },
      2: { cellWidth: 32, fontStyle: "bold", textColor: [180, 30, 30] },
      3: { cellWidth: 32 },
      4: { cellWidth: 49 }
    }
  });

  // Consolidated Full Ledger Table
  const allTableData = vulnerabilities.map(item => [
    item.id,
    item.name,
    item.category.toUpperCase(),
    formatExactCurrency(item.lossIfIgnored),
    formatExactCurrency(item.solutionCost),
    item.severity.toUpperCase(),
    item.recommendation
  ]);

  autoTable(doc, {
    startY: doc.lastAutoTable.finalY + 8,
    head: [["ID", "Vulnerability Finding", "Domain", "Est. Loss", "Fix Cost", "Severity", "Board Action"]],
    body: allTableData,
    theme: "plain",
    styles: { fontSize: 7, cellPadding: 2.2, textColor: [40, 45, 50], lineColor: [225, 230, 238], lineWidth: 0.2 },
    headStyles: { fillColor: [238, 241, 246], textColor: [30, 35, 45], fontStyle: "bold" },
    columnStyles: {
      0: { cellWidth: 14, fontStyle: "bold" },
      1: { cellWidth: 52 },
      2: { cellWidth: 20 },
      3: { cellWidth: 24, fontStyle: "bold", textColor: [180, 30, 30] },
      4: { cellWidth: 18 },
      5: { cellWidth: 18, fontStyle: "bold" },
      6: { cellWidth: 36 }
    },
    didParseCell: function(data) {
      if (data.section === 'body' && data.column.index === 5) {
        if (data.cell.raw === "SEVERE") data.cell.styles.textColor = severeRed;
        else if (data.cell.raw === "MEDIUM") data.cell.styles.textColor = mediumAmber;
        else data.cell.styles.textColor = ignorableGray;
      }
    }
  });

  // ================= SECTION: DETAILED DOSSIER FOR SEVERE FINDINGS =================
  doc.addPage();
  drawPageHeader(doc, "CRITICAL RISK DOSSIER — SEVERE ACTION ITEMS", "Immediate Board Action & Exploitation Blast Radius", companyName);
  renderVulnerabilityCards(doc, severeItems, 48);

  // ================= SECTION: DETAILED DOSSIER FOR MEDIUM FINDINGS =================
  doc.addPage();
  drawPageHeader(doc, "TACTICAL RISK DOSSIER — MEDIUM ROI ITEMS", "Sprint Remediation & Favorable ROI Mitigations", companyName);
  renderVulnerabilityCards(doc, mediumItems, 48);

  // ================= SECTION: NEGATIVE ROI RISK ACCEPTANCE =================
  doc.addPage();
  drawPageHeader(doc, "CAPITAL PRESERVATION — IGNORABLE FINDINGS (NEGATIVE ROI)", "Defensible Risk Acceptance where Fix Costs Exceed Loss Potential", companyName);
  renderVulnerabilityCards(doc, ignorableItems, 48);

  addPageFooters(doc);

  const filename = "executive_cyber_risk_quantification_master_dossier.pdf";
  doc.save(filename);
}

/**
 * Generates an executive 1-page single-vulnerability PDF dossier.
 */
export function generateSingleVulnerabilityReport(item, companyName = "Acme Global Enterprise") {
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

  drawPageHeader(
    doc,
    `RISK DOSSIER: ${item.id}`,
    item.name,
    companyName
  );

  // Top metric bar: 3 boxes
  const netSaved = Math.max(0, item.lossIfIgnored - item.solutionCost);

  // Box 1: Loss
  doc.setFillColor(248, 250, 252);
  doc.rect(14, 48, 56, 20, "F");
  doc.setDrawColor(...accentBorder);
  doc.setLineWidth(0.3);
  doc.rect(14, 48, 56, 20, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(6.8);
  doc.setTextColor(180, 40, 40);
  doc.text("EST. UNMITIGATED LOSS", 18, 54);
  doc.setFontSize(12);
  doc.setTextColor(...primaryColor);
  doc.text(formatExactCurrency(item.lossIfIgnored), 18, 63);

  // Box 2: Solution Cost
  doc.setFillColor(248, 250, 252);
  doc.rect(74, 48, 56, 20, "F");
  doc.rect(74, 48, 56, 20, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(6.8);
  doc.setTextColor(185, 120, 20);
  doc.text("ENGINEERING FIX SPEND", 78, 54);
  doc.setFontSize(12);
  doc.setTextColor(...primaryColor);
  doc.text(formatExactCurrency(item.solutionCost), 78, 63);

  // Box 3: Net Capital Saved
  doc.setFillColor(248, 250, 252);
  doc.rect(134, 48, 62, 20, "F");
  doc.rect(134, 48, 62, 20, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(6.8);
  doc.setTextColor(20, 140, 60);
  doc.text("NET VALUE PRESERVED", 138, 54);
  doc.setFontSize(12);
  doc.setTextColor(20, 140, 60);
  doc.text(`+${formatExactCurrency(netSaved)}`, 138, 63);

  // Meta breakdown
  let curY = 72;
  doc.setFillColor(240, 243, 248);
  doc.rect(14, curY, 182, 24, "F");
  doc.rect(14, curY, 182, 24, "S");

  doc.setFontSize(7.5);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(60, 70, 85);
  doc.text("SEVERITY TRIAGE:", 18, curY + 6);
  doc.text("TARGET GROUP:", 18, curY + 13);
  doc.text("TELEMETRY SOURCE:", 18, curY + 20);

  doc.setFont("helvetica", "normal");
  const sevColor = item.severity === "Severe" ? severeRed : (item.severity === "Medium" ? mediumAmber : ignorableGray);
  doc.setTextColor(...sevColor);
  doc.text(`${item.severity.toUpperCase()} (${item.annualProbability || '70% Likelihood'})`, 55, curY + 6);
  doc.setTextColor(40, 45, 55);
  doc.text(item.targetGroup || "Enterprise Assets", 55, curY + 13);
  doc.text(item.source || "SIEM + EDR + IAM", 55, curY + 20);

  doc.setFont("helvetica", "bold");
  doc.setTextColor(60, 70, 85);
  doc.text("THREAT PROFILE:", 110, curY + 6);
  doc.text("ATTACK VECTOR / CVE:", 110, curY + 13);
  doc.text("COMPLIANCE STATUTE:", 110, curY + 20);

  doc.setFont("helvetica", "normal");
  doc.setTextColor(40, 45, 55);
  doc.text(item.threatActor || "Opportunistic Threat Actor", 146, curY + 6);
  doc.text(`${item.attackVector || "T1190"} (${item.cveList || "CWE-699"})`, 146, curY + 13);
  doc.text(item.complianceImpact || "SOC 2 Type II, ISO 27001", 146, curY + 20);

  curY += 28;

  // Section 1: Technical Finding
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(...primaryColor);
  doc.text("1. TELEMETRY EVIDENCE & TECHNICAL FINDING", 14, curY);
  curY += 4.5;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(50, 55, 65);
  const tfLines = doc.splitTextToSize(item.technicalFinding || "Telemetry anomaly confirmed.", 182);
  doc.text(tfLines, 14, curY);
  curY += (tfLines.length * 3.8) + 5;

  // Section 2: Actuarial Business Impact
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(...primaryColor);
  doc.text("2. ACTUARIAL BUSINESS IMPACT & LOSS MODELING", 14, curY);
  curY += 4.5;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(50, 55, 65);
  const biLines = doc.splitTextToSize(item.businessImpact || "Operational and financial disruption risk.", 182);
  doc.text(biLines, 14, curY);
  curY += (biLines.length * 3.8) + 3;

  if (item.lossBreakdown) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.setTextColor(180, 40, 40);
    doc.text(`Loss Breakdown: ${item.lossBreakdown}`, 14, curY);
    curY += 6;
  } else {
    curY += 3;
  }

  // Section 3: Engineering Roadmap & Recommendation
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(...primaryColor);
  doc.text("3. ENGINEERING REMEDIATION ROADMAP", 14, curY);
  curY += 4.5;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(20, 110, 50);
  const spLines = doc.splitTextToSize(item.solutionPlan || "Implement multi-phase mitigation.", 182);
  doc.text(spLines, 14, curY);
  curY += (spLines.length * 3.8) + 6;

  // Strategic Recommendation Box
  doc.setFillColor(242, 246, 252);
  doc.rect(14, curY, 182, 14, "F");
  doc.setDrawColor(180, 200, 230);
  doc.rect(14, curY, 182, 14, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(...primaryColor);
  doc.text("STRATEGIC BOARD RECOMMENDATION:", 18, curY + 5.5);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(40, 50, 70);
  doc.text(item.recommendation || "Remediate in Sprint (Positive ROI)", 18, curY + 10);

  addPageFooters(doc);

  const cleanId = String(item.id).toLowerCase().replace(/[^a-z0-9_-]/g, "_");
  const cleanName = String(companyName).toLowerCase().replace(/[^a-z0-9_-]/g, "_");
  doc.save(`risk_brief_${cleanId}_${cleanName}.pdf`);
}
