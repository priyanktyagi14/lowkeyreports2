import React, { useState, useEffect, useMemo } from "react";
import { formatCurrency, formatExactCurrency } from "../data/telemetryData";
import {
  generateCategoryReport,
  generateMasterReport,
  generateSingleVulnerabilityReport
} from "../utils/pdfGenerator";

export function DashboardView({
  vulnerabilities = [],
  telemetrySummary,
  companyName = "Acme Global Enterprise",
  setCompanyName
}) {
  // Scroll to top when the dashboard loads
  useEffect(() => {
    window.scrollTo(0, 0);
  }, []);

  const [activeCategory, setActiveCategory] = useState("all");
  const [downloadingCategory, setDownloadingCategory] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [toastMessage, setToastMessage] = useState(null);
  const [showComplianceModal, setShowComplianceModal] = useState(false);
  const [isEditingCompany, setIsEditingCompany] = useState(false);
  const [tempCompanyName, setTempCompanyName] = useState(companyName);

  // Search, Filter & Sort states
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [sortBy, setSortBy] = useState("loss-desc");

  // What-If Scenario decisions: [id] -> 'planned' | 'accepted' | 'deferred'
  const [decisions, setDecisions] = useState(() => {
    const init = {};
    vulnerabilities.forEach((v) => {
      init[v.id] = v.severity === "Ignorable" ? "accepted" : "planned";
    });
    return init;
  });

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  // Dynamic Actuarial Recalculation based on What-If decisions
  const dynamicMetrics = useMemo(() => {
    let totalLoss = 0;
    let totalCost = 0;
    let plannedLossPrevented = 0;
    let severeCount = 0;
    let mediumCount = 0;
    let ignorableCount = 0;
    let plannedCount = 0;
    let acceptedCount = 0;
    let deferredCount = 0;

    vulnerabilities.forEach((item) => {
      totalLoss += item.lossIfIgnored;

      if (item.severity === "Severe") severeCount++;
      else if (item.severity === "Medium") mediumCount++;
      else if (item.severity === "Ignorable") ignorableCount++;

      const decision = decisions[item.id] || (item.severity === "Ignorable" ? "accepted" : "planned");

      if (decision === "planned") {
        plannedCount++;
        totalCost += item.solutionCost;
        plannedLossPrevented += item.lossIfIgnored;
      } else if (decision === "accepted") {
        acceptedCount++;
      } else if (decision === "deferred") {
        deferredCount++;
      }
    });

    const netSavings = plannedLossPrevented - totalCost;

    return {
      totalLoss,
      totalCost,
      netSavings,
      totalCount: vulnerabilities.length,
      severeCount,
      mediumCount,
      ignorableCount,
      plannedCount,
      acceptedCount,
      deferredCount
    };
  }, [vulnerabilities, decisions]);

  const handleDecisionToggle = (e, id, newDecision) => {
    e.stopPropagation();
    setDecisions((prev) => ({
      ...prev,
      [id]: newDecision
    }));
  };

  const handleScenarioOptimal = () => {
    const next = {};
    vulnerabilities.forEach((v) => {
      next[v.id] = v.severity === "Ignorable" ? "accepted" : "planned";
    });
    setDecisions(next);
    showToast("Applied Optimal ROI Plan: Severe & Medium remediated, Ignorable accepted.");
  };

  const handleScenarioFixAll = () => {
    const next = {};
    vulnerabilities.forEach((v) => {
      next[v.id] = "planned";
    });
    setDecisions(next);
    showToast("Applied 100% Blanket Remediation Scenario.");
  };

  const handleScenarioReset = () => {
    handleScenarioOptimal();
  };

  // Filter & Sort Logic
  const filteredVulnerabilities = useMemo(() => {
    return vulnerabilities
      .filter((v) => {
        // Tab category
        if (activeCategory !== "all" && v.category !== activeCategory) {
          return false;
        }
        // Severity filter
        if (severityFilter !== "all" && v.severity.toLowerCase() !== severityFilter) {
          return false;
        }
        // Source filter
        if (sourceFilter !== "all") {
          const s = (v.source || "").toLowerCase();
          if (!s.includes(sourceFilter)) return false;
        }
        // Search query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const match =
            v.id.toLowerCase().includes(q) ||
            v.name.toLowerCase().includes(q) ||
            (v.targetGroup && v.targetGroup.toLowerCase().includes(q)) ||
            (v.cveList && v.cveList.toLowerCase().includes(q)) ||
            (v.attackVector && v.attackVector.toLowerCase().includes(q)) ||
            (v.technicalFinding && v.technicalFinding.toLowerCase().includes(q)) ||
            (v.threatActor && v.threatActor.toLowerCase().includes(q));
          if (!match) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === "loss-desc") return b.lossIfIgnored - a.lossIfIgnored;
        if (sortBy === "loss-asc") return a.lossIfIgnored - b.lossIfIgnored;
        if (sortBy === "cost-desc") return b.solutionCost - a.solutionCost;
        if (sortBy === "cost-asc") return a.solutionCost - b.solutionCost;
        if (sortBy === "severity") {
          const order = { Severe: 3, Medium: 2, Ignorable: 1 };
          return (order[b.severity] || 0) - (order[a.severity] || 0);
        }
        if (sortBy === "id") return a.id.localeCompare(b.id);
        return 0;
      });
  }, [vulnerabilities, activeCategory, severityFilter, sourceFilter, searchQuery, sortBy]);

  // PDF Downloads
  const handleDownload = (categoryKey) => {
    setDownloadingCategory(categoryKey);
    try {
      generateCategoryReport(categoryKey, vulnerabilities, companyName);
      showToast(`Generated ${categoryKey.toUpperCase()} Report for ${companyName}.`);
    } catch (err) {
      console.error("PDF generation failed:", err);
      showToast("PDF generation failed.");
    } finally {
      setTimeout(() => setDownloadingCategory(null), 800);
    }
  };

  const handleDownloadMaster = () => {
    setDownloadingCategory("master");
    try {
      generateMasterReport(vulnerabilities, companyName);
      showToast(`Generated Master Executive Dossier for ${companyName}.`);
    } catch (err) {
      console.error("Master PDF generation failed:", err);
      showToast("Master PDF generation failed.");
    } finally {
      setTimeout(() => setDownloadingCategory(null), 1000);
    }
  };

  const handleDownloadSinglePdf = (e, item) => {
    e.stopPropagation();
    try {
      generateSingleVulnerabilityReport(item, companyName);
      showToast(`Downloaded 1-page risk brief for [${item.id}].`);
    } catch (err) {
      console.error("Single PDF generation failed:", err);
      showToast("Error generating 1-page PDF.");
    }
  };

  const handleCopyPlan = (e, item) => {
    e.stopPropagation();
    const text = `[${item.id}] ${item.name}\nTarget: ${item.targetGroup}\nSeverity: ${item.severity}\nLoss: ${formatExactCurrency(item.lossIfIgnored)} | Fix Cost: ${formatExactCurrency(item.solutionCost)}\nRemediation Plan:\n${item.solutionPlan}\nRecommendation: ${item.recommendation}`;
    navigator.clipboard.writeText(text);
    setCopiedId(item.id);
    setTimeout(() => setCopiedId(null), 2000);
    showToast(`Copied remediation plan for [${item.id}] to clipboard!`);
  };

  // CSV Export
  const handleExportCsv = () => {
    const headers = [
      "ID",
      "Category",
      "Name",
      "Target Group",
      "Telemetry Source",
      "Est Loss If Ignored ($)",
      "Solution Cost ($)",
      "Severity",
      "Annual Likelihood",
      "Threat Actor",
      "Attack Vector",
      "CVE List",
      "Compliance Impact",
      "Decision Status",
      "Recommendation"
    ];

    const rows = vulnerabilities.map((v) => [
      v.id,
      v.category,
      `"${(v.name || "").replace(/"/g, '""')}"`,
      `"${(v.targetGroup || "").replace(/"/g, '""')}"`,
      `"${(v.source || "").replace(/"/g, '""')}"`,
      v.lossIfIgnored,
      v.solutionCost,
      v.severity,
      `"${(v.annualProbability || "").replace(/"/g, '""')}"`,
      `"${(v.threatActor || "").replace(/"/g, '""')}"`,
      `"${(v.attackVector || "").replace(/"/g, '""')}"`,
      `"${(v.cveList || "").replace(/"/g, '""')}"`,
      `"${(v.complianceImpact || "").replace(/"/g, '""')}"`,
      decisions[v.id] || "planned",
      `"${(v.recommendation || "").replace(/"/g, '""')}"`
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `cyber_risk_ledger_${companyName.toLowerCase().replace(/[^a-z0-9_-]/g, "_")}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast("Exported CSV spreadsheet.");
  };

  // JSON Export
  const handleExportJson = () => {
    const payload = {
      companyName,
      auditTimestamp: new Date().toISOString(),
      summaryMetrics: dynamicMetrics,
      vulnerabilities: vulnerabilities.map((v) => ({
        ...v,
        remediationDecision: decisions[v.id] || "planned"
      }))
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(payload, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", dataStr);
    link.setAttribute("download", `cyber_risk_dossier_${companyName.toLowerCase().replace(/[^a-z0-9_-]/g, "_")}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast("Exported JSON dossier.");
  };

  const toggleExpand = (id) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  // SEC Disclosure Items (Loss >= $1,000,000)
  const secDisclosureItems = vulnerabilities.filter((v) => v.lossIfIgnored >= 1000000);

  return (
    <main className="dashboard-main">
      {/* Toast Notification Banner */}
      {toastMessage && (
        <div
          style={{
            position: "fixed",
            bottom: "24px",
            right: "24px",
            zIndex: 9999,
            background: "var(--bg-card)",
            border: "1px solid var(--border-strong)",
            color: "var(--text-primary)",
            padding: "10px 18px",
            fontFamily: "var(--font-mono)",
            fontSize: "12px",
            boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
            borderRadius: "2px",
            display: "flex",
            alignItems: "center",
            gap: "10px"
          }}
        >
          <span style={{ color: "var(--color-positive)" }}>✓</span>
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Target Organization Header Bar */}
      <div
        className="entity-header-bar"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "12px 20px",
          background: "var(--bg-card)",
          border: "1px solid var(--border-color)",
          marginBottom: "24px",
          borderRadius: "2px"
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              color: "var(--text-tertiary)",
              letterSpacing: "0.06em"
            }}
          >
            TARGET ENTERPRISE:
          </span>
          {isEditingCompany ? (
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <input
                type="text"
                value={tempCompanyName}
                onChange={(e) => setTempCompanyName(e.target.value)}
                style={{
                  background: "var(--bg-main)",
                  border: "1px solid var(--border-strong)",
                  color: "var(--text-primary)",
                  padding: "4px 8px",
                  fontSize: "13px",
                  borderRadius: "2px",
                  outline: "none"
                }}
              />
              <button
                type="button"
                className="btn-file-select"
                style={{ padding: "4px 10px", fontSize: "11px" }}
                onClick={() => {
                  setCompanyName && setCompanyName(tempCompanyName);
                  setIsEditingCompany(false);
                  showToast(`Updated entity name to "${tempCompanyName}".`);
                }}
              >
                SAVE
              </button>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <strong style={{ color: "var(--text-primary)", fontSize: "14px" }}>
                {companyName}
              </strong>
              <button
                type="button"
                onClick={() => {
                  setTempCompanyName(companyName);
                  setIsEditingCompany(true);
                }}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "var(--text-tertiary)",
                  cursor: "pointer",
                  fontSize: "12px",
                  padding: "2px 6px"
                }}
                title="Edit organization name"
              >
                ✎ EDIT
              </button>
            </div>
          )}
        </div>

        <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
          <button
            type="button"
            className="btn-secondary-action"
            style={{ padding: "6px 12px", fontSize: "11px" }}
            onClick={() => setShowComplianceModal(true)}
          >
            ⚖ STATUTORY COMPLIANCE MATRIX (SEC / SOC 2)
          </button>
          <button
            type="button"
            className="btn-secondary-action"
            style={{ padding: "6px 12px", fontSize: "11px" }}
            onClick={handleExportCsv}
          >
            EXPORT CSV
          </button>
          <button
            type="button"
            className="btn-secondary-action"
            style={{ padding: "6px 12px", fontSize: "11px" }}
            onClick={handleExportJson}
          >
            EXPORT JSON
          </button>
        </div>
      </div>

      {/* ===================== HERO SECTION ===================== */}
      <section className="dashboard-hero">
        {/* HALF OF HERO: 3 BIG CIRCLES */}
        <div className="hero-circles-col">
          {/* Circle 1: Est. Loss */}
          <div className="stat-circle-card loss">
            <span className="circle-tag">EST. LOSS</span>
            <div className="circle-value">{formatCurrency(dynamicMetrics.totalLoss)}</div>
            <div className="circle-micro-desc">
              Unmitigated exposure if all telemetry findings remain unpatched
            </div>
          </div>

          {/* Circle 2: Est. Solution Cost */}
          <div className="stat-circle-card cost">
            <span className="circle-tag">PLANNED FIX SPEND</span>
            <div className="circle-value">{formatCurrency(dynamicMetrics.totalCost)}</div>
            <div className="circle-micro-desc">
              Capital allocated for {dynamicMetrics.plannedCount} active planned remediations
            </div>
          </div>

          {/* Circle 3: Net Saved */}
          <div className="stat-circle-card net">
            <span className="circle-tag">NET CAPITAL PRESERVED</span>
            <div className="circle-value">+{formatCurrency(dynamicMetrics.netSavings)}</div>
            <div className="circle-micro-desc">
              Net balance sheet value preserved by targeted remediation
            </div>
          </div>
        </div>

        {/* REST OF HERO: DOWNLOAD BUTTONS & WHAT-IF CONTROLS */}
        <div className="hero-content-col">
          <div className="hero-header-tag">BOARD EXECUTIVE SUMMARY // FAIR ANSI/O-RA</div>
          <h2 className="hero-heading">Dollar-Quantified Cyber Exposure</h2>
          <p className="hero-description">
            Technical SIEM, EDR, and IAM signals translated into defensible financial metrics via Local Laya AI. Blanket remediation of every minor alert destroys engineering capital; our actuarial model identifies high-leverage threats while deprioritizing negative-ROI findings.
          </p>

          {/* Interactive What-If Scenario Toolbar */}
          <div
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-color)",
              padding: "10px 14px",
              marginBottom: "16px",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "10px"
            }}
          >
            <div style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
              WHAT-IF SANDBOX: <strong>{dynamicMetrics.plannedCount}</strong> Remediate ·{" "}
              <strong>{dynamicMetrics.acceptedCount}</strong> Accept Risk ·{" "}
              <strong>{dynamicMetrics.deferredCount}</strong> Defer
            </div>
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                type="button"
                className="btn-file-select"
                style={{ padding: "4px 8px", fontSize: "10px" }}
                onClick={handleScenarioOptimal}
                title="Auto-plan Severe and Medium findings, accept risk on Ignorable items"
              >
                ⚡ OPTIMAL ROI PLAN
              </button>
              <button
                type="button"
                className="btn-file-select"
                style={{ padding: "4px 8px", fontSize: "10px" }}
                onClick={handleScenarioFixAll}
                title="Model 100% remediation spend across all items"
              >
                🛡️ FIX ALL
              </button>
              <button
                type="button"
                className="btn-file-select"
                style={{ padding: "4px 8px", fontSize: "10px" }}
                onClick={handleScenarioReset}
                title="Reset scenario to standard default"
              >
                ↺ RESET
              </button>
            </div>
          </div>

          <div className="hero-download-buttons-group">
            {/* MASTER COMPREHENSIVE REPORT BUTTON */}
            <button
              type="button"
              className="btn-report-download master-btn"
              onClick={handleDownloadMaster}
              disabled={downloadingCategory === "master"}
            >
              <div className="btn-left">
                <span className="btn-number">★ MASTER</span>
                <span>Download Master Executive Dossier (All 3 Domains)</span>
              </div>
              <span className="btn-ext">
                {downloadingCategory === "master" ? "GENERATING..." : ".PDF"}
              </span>
            </button>

            <button
              type="button"
              className="btn-report-download"
              onClick={() => handleDownload("internal")}
              disabled={downloadingCategory === "internal"}
            >
              <div className="btn-left">
                <span className="btn-number">01</span>
                <span>Download Internal Report (Employees & Devs)</span>
              </div>
              <span className="btn-ext">
                {downloadingCategory === "internal" ? "GENERATING..." : ".PDF"}
              </span>
            </button>

            <button
              type="button"
              className="btn-report-download"
              onClick={() => handleDownload("external")}
              disabled={downloadingCategory === "external"}
            >
              <div className="btn-left">
                <span className="btn-number">02</span>
                <span>Download External Report (Customers & Vendors)</span>
              </div>
              <span className="btn-ext">
                {downloadingCategory === "external" ? "GENERATING..." : ".PDF"}
              </span>
            </button>

            <button
              type="button"
              className="btn-report-download"
              onClick={() => handleDownload("machines")}
              disabled={downloadingCategory === "machines"}
            >
              <div className="btn-left">
                <span className="btn-number">03</span>
                <span>Download Machines Report (Servers & Infra)</span>
              </div>
              <span className="btn-ext">
                {downloadingCategory === "machines" ? "GENERATING..." : ".PDF"}
              </span>
            </button>
          </div>
        </div>
      </section>

      {/* ===================== 4 VULNERABILITY COUNT BOXES ===================== */}
      <section className="counts-section">
        <div className="counts-grid">
          <div
            className={`count-box total ${severityFilter === "all" ? "active-filter" : ""}`}
            style={{ cursor: "pointer" }}
            onClick={() => setSeverityFilter("all")}
          >
            <div className="count-box-label">Total Findings</div>
            <div className="count-box-number">{dynamicMetrics.totalCount}</div>
            <div className="count-box-explanation">
              Cross-correlated events across SIEM, EDR, and IAM telemetry feeds.
            </div>
          </div>

          <div
            className={`count-box severe ${severityFilter === "severe" ? "active-filter" : ""}`}
            style={{ cursor: "pointer" }}
            onClick={() => setSeverityFilter((prev) => (prev === "severe" ? "all" : "severe"))}
          >
            <div className="count-box-label">Severe Vulnerabilities</div>
            <div className="count-box-number">{dynamicMetrics.severeCount}</div>
            <div className="count-box-explanation">
              Critical blast radius with immediate exploitability. Immediate board priority.
            </div>
          </div>

          <div
            className={`count-box medium ${severityFilter === "medium" ? "active-filter" : ""}`}
            style={{ cursor: "pointer" }}
            onClick={() => setSeverityFilter((prev) => (prev === "medium" ? "all" : "medium"))}
          >
            <div className="count-box-label">Medium Vulnerabilities</div>
            <div className="count-box-number">{dynamicMetrics.mediumCount}</div>
            <div className="count-box-explanation">
              Substantial exposure with highly favorable remediation return on investment.
            </div>
          </div>

          <div
            className={`count-box ignorable ${severityFilter === "ignorable" ? "active-filter" : ""}`}
            style={{ cursor: "pointer" }}
            onClick={() => setSeverityFilter((prev) => (prev === "ignorable" ? "all" : "ignorable"))}
          >
            <div className="count-box-label">Ignorable (Negative ROI)</div>
            <div className="count-box-number">{dynamicMetrics.ignorableCount}</div>
            <div className="count-box-explanation">
              Remediation cost exceeds potential breach impact. Explicitly advised to accept risk.
            </div>
          </div>
        </div>
      </section>

      {/* ===================== TABLE SECTION WITH FILTER & SEARCH ===================== */}
      <section className="table-section">
        <div className="table-header-bar">
          <div className="table-header-title-block">
            <h3>Vulnerability Ledger & Remediation Triage</h3>
            <p>
              Showing {filteredVulnerabilities.length} of {vulnerabilities.length} findings. Toggle action pill or click row to inspect dossier.
            </p>
          </div>

          {/* 4-WAY DOMAIN TOGGLE */}
          <div className="toggle-group" role="tablist">
            <button
              type="button"
              className={`toggle-btn ${activeCategory === "all" ? "active" : ""}`}
              onClick={() => setActiveCategory("all")}
            >
              ALL DOMAINS ({vulnerabilities.length})
            </button>
            <button
              type="button"
              className={`toggle-btn ${activeCategory === "internal" ? "active" : ""}`}
              onClick={() => setActiveCategory("internal")}
            >
              INTERNAL (PEOPLE & DEVS)
            </button>
            <button
              type="button"
              className={`toggle-btn ${activeCategory === "external" ? "active" : ""}`}
              onClick={() => setActiveCategory("external")}
            >
              EXTERNAL (CUSTOMERS & VENDORS)
            </button>
            <button
              type="button"
              className={`toggle-btn ${activeCategory === "machines" ? "active" : ""}`}
              onClick={() => setActiveCategory("machines")}
            >
              MACHINES (SERVERS & INFRA)
            </button>
          </div>
        </div>

        {/* LEDGER SEARCH & FILTER TOOLBAR */}
        <div
          className="ledger-toolbar"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "12px",
            padding: "12px 16px",
            background: "var(--bg-card)",
            border: "1px solid var(--border-color)",
            borderBottom: "none"
          }}
        >
          {/* Search box */}
          <div style={{ flex: 1, minWidth: "260px" }}>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="🔍 Search findings, CVEs, MITRE vectors, keywords..."
              style={{
                width: "100%",
                background: "var(--bg-main)",
                border: "1px solid var(--border-strong)",
                color: "var(--text-primary)",
                padding: "8px 12px",
                fontFamily: "var(--font-sans)",
                fontSize: "13px",
                borderRadius: "2px",
                outline: "none"
              }}
            />
          </div>

          {/* Source filter */}
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <label style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
              SOURCE:
            </label>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              style={{
                background: "var(--bg-main)",
                border: "1px solid var(--border-strong)",
                color: "var(--text-primary)",
                padding: "6px 10px",
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                borderRadius: "2px",
                outline: "none"
              }}
            >
              <option value="all">All Telemetry Sources</option>
              <option value="siem">SIEM Logs</option>
              <option value="edr">EDR Agents</option>
              <option value="iam">IAM Identities</option>
            </select>
          </div>

          {/* Sort By */}
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <label style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
              SORT BY:
            </label>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              style={{
                background: "var(--bg-main)",
                border: "1px solid var(--border-strong)",
                color: "var(--text-primary)",
                padding: "6px 10px",
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                borderRadius: "2px",
                outline: "none"
              }}
            >
              <option value="loss-desc">Highest Loss ($)</option>
              <option value="loss-asc">Lowest Loss ($)</option>
              <option value="cost-desc">Highest Fix Cost ($)</option>
              <option value="cost-asc">Lowest Fix Cost ($)</option>
              <option value="severity">Severity (Severe → Ignorable)</option>
              <option value="id">Finding ID (A → Z)</option>
            </select>
          </div>

          {(searchQuery || severityFilter !== "all" || sourceFilter !== "all") && (
            <button
              type="button"
              className="btn-file-select"
              style={{ padding: "6px 10px", fontSize: "11px" }}
              onClick={() => {
                setSearchQuery("");
                setSeverityFilter("all");
                setSourceFilter("all");
              }}
            >
              CLEAR FILTERS
            </button>
          )}
        </div>

        {/* SINGLE ACTIVE TABLE */}
        <div className="table-wrapper">
          <table className="crq-table">
            <thead>
              <tr>
                <th style={{ width: "70px" }}>ID</th>
                <th style={{ width: "240px" }}>Vulnerability & Target</th>
                <th style={{ width: "95px" }}>Telemetry</th>
                <th style={{ width: "125px" }}>Est. Loss If Ignored</th>
                <th style={{ width: "110px" }}>Fix Cost</th>
                <th style={{ width: "95px" }}>Severity</th>
                <th style={{ width: "135px" }}>What-If Action</th>
                <th>Board Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {filteredVulnerabilities.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: "center", padding: "40px", color: "var(--text-tertiary)" }}>
                    No findings matched your filter or search criteria.
                  </td>
                </tr>
              ) : (
                filteredVulnerabilities.map((item) => {
                  const isExpanded = expandedId === item.id;
                  const currentDecision = decisions[item.id] || (item.severity === "Ignorable" ? "accepted" : "planned");

                  return (
                    <React.Fragment key={item.id}>
                      <tr
                        className={`crq-row-interactive ${isExpanded ? "is-expanded" : ""}`}
                        onClick={() => toggleExpand(item.id)}
                        title="Click to view full actuarial risk dossier"
                      >
                        <td className="col-id">
                          <button
                            type="button"
                            className="expand-toggle-btn"
                            aria-label="Toggle details"
                          >
                            {isExpanded ? "▲" : "▼"}
                          </button>
                          {item.id}
                        </td>
                        <td>
                          <div className="col-name-box">
                            <span className="finding-title">{item.name}</span>
                            <span className="finding-target">{item.targetGroup}</span>
                          </div>
                        </td>
                        <td>
                          <span
                            style={{
                              fontFamily: "var(--font-mono)",
                              fontSize: "10.5px",
                              color: "var(--text-secondary)"
                            }}
                          >
                            {item.source}
                          </span>
                        </td>
                        <td className="col-currency col-loss">
                          {formatExactCurrency(item.lossIfIgnored)}
                        </td>
                        <td className="col-currency col-cost">
                          {formatExactCurrency(item.solutionCost)}
                        </td>
                        <td>
                          <span className={`badge-severity ${item.severity.toLowerCase()}`}>
                            {item.severity}
                          </span>
                        </td>
                        {/* Interactive What-If Decision Column */}
                        <td onClick={(e) => e.stopPropagation()}>
                          <div style={{ display: "flex", gap: "4px" }}>
                            <button
                              type="button"
                              onClick={(e) => handleDecisionToggle(e, item.id, "planned")}
                              title="Plan engineering remediation"
                              style={{
                                padding: "3px 6px",
                                fontSize: "10px",
                                fontFamily: "var(--font-mono)",
                                border: "1px solid",
                                borderRadius: "2px",
                                cursor: "pointer",
                                background: currentDecision === "planned" ? "var(--color-severe)" : "transparent",
                                color: currentDecision === "planned" ? "#fff" : "var(--text-secondary)",
                                borderColor: currentDecision === "planned" ? "var(--color-severe)" : "var(--border-color)"
                              }}
                            >
                              FIX
                            </button>
                            <button
                              type="button"
                              onClick={(e) => handleDecisionToggle(e, item.id, "accepted")}
                              title="Accept risk (avoid fix spend)"
                              style={{
                                padding: "3px 6px",
                                fontSize: "10px",
                                fontFamily: "var(--font-mono)",
                                border: "1px solid",
                                borderRadius: "2px",
                                cursor: "pointer",
                                background: currentDecision === "accepted" ? "var(--color-ignorable)" : "transparent",
                                color: currentDecision === "accepted" ? "#fff" : "var(--text-secondary)",
                                borderColor: currentDecision === "accepted" ? "var(--color-ignorable)" : "var(--border-color)"
                              }}
                            >
                              ACCEPT
                            </button>
                            <button
                              type="button"
                              onClick={(e) => handleDecisionToggle(e, item.id, "deferred")}
                              title="Defer decision to next quarter"
                              style={{
                                padding: "3px 6px",
                                fontSize: "10px",
                                fontFamily: "var(--font-mono)",
                                border: "1px solid",
                                borderRadius: "2px",
                                cursor: "pointer",
                                background: currentDecision === "deferred" ? "var(--color-medium)" : "transparent",
                                color: currentDecision === "deferred" ? "#fff" : "var(--text-secondary)",
                                borderColor: currentDecision === "deferred" ? "var(--color-medium)" : "var(--border-color)"
                              }}
                            >
                              DEFER
                            </button>
                          </div>
                        </td>
                        <td className="col-rec">
                          <div style={{ fontWeight: 600 }}>{item.recommendation}</div>
                          <div
                            style={{
                              fontSize: "10.5px",
                              color: "var(--text-tertiary)",
                              marginTop: "2px"
                            }}
                          >
                            {item.attackVector ? `MITRE: ${item.attackVector}` : item.technicalFinding}
                          </div>
                        </td>
                      </tr>

                      {/* EXPANDED DOSSIER DETAILS PANEL */}
                      {isExpanded && (
                        <tr className="dossier-expand-row">
                          <td colSpan={8}>
                            <div className="dossier-card">
                              <div className="dossier-grid-header">
                                <div className="dossier-title">
                                  [{item.id}] Actuarial Deep-Dive Risk Dossier — {companyName}
                                </div>
                                <div className="dossier-badge-row" style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                                  <button
                                    type="button"
                                    className="btn-file-select"
                                    style={{ padding: "4px 8px", fontSize: "10.5px" }}
                                    onClick={(e) => handleDownloadSinglePdf(e, item)}
                                    title="Download 1-page board PDF for this finding"
                                  >
                                    📄 DOWNLOAD 1-PAGER (.PDF)
                                  </button>
                                  <button
                                    type="button"
                                    className="btn-file-select"
                                    style={{ padding: "4px 8px", fontSize: "10.5px" }}
                                    onClick={(e) => handleCopyPlan(e, item)}
                                    title="Copy phased solution plan to clipboard"
                                  >
                                    {copiedId === item.id ? "✓ COPIED" : "📋 COPY PLAN"}
                                  </button>
                                  <span className={`badge-severity ${item.severity.toLowerCase()}`}>
                                    {item.severity} SEVERITY
                                  </span>
                                  <span
                                    style={{
                                      fontFamily: "var(--font-mono)",
                                      fontSize: "10.5px",
                                      color: "var(--text-secondary)"
                                    }}
                                  >
                                    {item.annualProbability || "70% Annualized Likelihood"}
                                  </span>
                                </div>
                              </div>

                              <div className="dossier-meta-grid">
                                <div className="dossier-meta-item">
                                  <div className="meta-label">THREAT ADVERSARY PROFILE</div>
                                  <div className="meta-val">
                                    {item.threatActor || "Opportunistic Cyber Threat Actor"}
                                  </div>
                                </div>
                                <div className="dossier-meta-item">
                                  <div className="meta-label">MITRE ATT&CK / CVE</div>
                                  <div className="meta-val">
                                    {item.attackVector || "T1190"} ({item.cveList || "CWE-699"})
                                  </div>
                                </div>
                                <div className="dossier-meta-item">
                                  <div className="meta-label">STATUTORY COMPLIANCE IMPACT</div>
                                  <div className="meta-val">
                                    {item.complianceImpact || "SOC 2 Type II, ISO 27001"}
                                  </div>
                                </div>
                              </div>

                              <div className="dossier-sections-grid">
                                <div className="dossier-section-block">
                                  <div className="section-label">TELEMETRY TECHNICAL EVIDENCE</div>
                                  <div className="section-body">{item.technicalFinding}</div>
                                </div>

                                <div className="dossier-section-block">
                                  <div className="section-label">ACTUARIAL BUSINESS IMPACT & LOSS BREAKDOWN</div>
                                  <div className="section-body">
                                    {item.businessImpact}
                                    {item.lossBreakdown && (
                                      <div
                                        style={{
                                          marginTop: "6px",
                                          fontFamily: "var(--font-mono)",
                                          fontSize: "11px",
                                          color: "var(--color-severe)"
                                        }}
                                      >
                                        {item.lossBreakdown}
                                      </div>
                                    )}
                                  </div>
                                </div>

                                <div className="dossier-section-block full-width">
                                  <div className="section-label">ENGINEERING REMEDIATION ROADMAP</div>
                                  <div
                                    className="section-body"
                                    style={{ color: "var(--color-positive)", fontWeight: 500 }}
                                  >
                                    {item.solutionPlan}
                                  </div>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* STATUTORY COMPLIANCE MODAL */}
      {showComplianceModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 99999,
            background: "rgba(0,0,0,0.75)",
            backdropFilter: "blur(4px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "20px"
          }}
          onClick={() => setShowComplianceModal(false)}
        >
          <div
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-strong)",
              maxWidth: "800px",
              width: "100%",
              maxHeight: "85vh",
              overflowY: "auto",
              padding: "24px",
              boxShadow: "0 16px 40px rgba(0,0,0,0.8)"
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "16px" }}>
              <div>
                <span style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--color-medium)" }}>
                  REGULATORY & AUDIT GOVERNANCE
                </span>
                <h3 style={{ margin: "4px 0", fontSize: "20px", color: "var(--text-primary)" }}>
                  Statutory Cyber Compliance Matrix — {companyName}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowComplianceModal(false)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "var(--text-secondary)",
                  fontSize: "18px",
                  cursor: "pointer"
                }}
              >
                ✕
              </button>
            </div>

            {/* SEC Item 1.05 Box */}
            <div
              style={{
                background: "var(--bg-main)",
                border: "1px solid var(--color-severe-border)",
                padding: "16px",
                marginBottom: "16px"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <strong style={{ color: "var(--color-severe)", fontSize: "14px" }}>
                  SEC 4-Day Material Cybersecurity Incident Rule (Item 1.05)
                </strong>
                <span className="badge-severity severe">{secDisclosureItems.length} QUALIFYING FINDINGS</span>
              </div>
              <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: "8px 0" }}>
                Under the SEC mandate, any cybersecurity event presenting material financial impact ($1M+ unmitigated exposure) triggers compulsory public Form 8-K disclosure within 4 business days.
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "10px" }}>
                {secDisclosureItems.map((item) => (
                  <div
                    key={item.id}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      fontSize: "12px",
                      fontFamily: "var(--font-mono)",
                      background: "rgba(239, 68, 68, 0.08)",
                      padding: "6px 10px",
                      borderRadius: "2px"
                    }}
                  >
                    <span>[{item.id}] {item.name}</span>
                    <strong style={{ color: "var(--color-severe)" }}>{formatExactCurrency(item.lossIfIgnored)}</strong>
                  </div>
                ))}
              </div>
            </div>

            {/* SOC 2 & ISO Framework Table */}
            <div style={{ background: "var(--bg-main)", border: "1px solid var(--border-color)", padding: "16px" }}>
              <strong style={{ color: "var(--text-primary)", fontSize: "13px" }}>
                SOC 2 Type II & ISO 27001 Control Mapping
              </strong>
              <table style={{ width: "100%", marginTop: "10px", fontSize: "12px", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border-color)", color: "var(--text-tertiary)" }}>
                    <th style={{ textAlign: "left", padding: "6px" }}>Control Code</th>
                    <th style={{ textAlign: "left", padding: "6px" }}>Control Domain</th>
                    <th style={{ textAlign: "left", padding: "6px" }}>Mapped Findings</th>
                    <th style={{ textAlign: "left", padding: "6px" }}>Compliance Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr style={{ borderBottom: "1px solid var(--border-color)" }}>
                    <td style={{ padding: "8px 6px", fontFamily: "var(--font-mono)" }}>SOC 2 CC6.1</td>
                    <td style={{ padding: "8px 6px" }}>Logical & Boundary Perimeter Controls</td>
                    <td style={{ padding: "8px 6px" }}>EXT-01, EXT-02, MCH-01</td>
                    <td style={{ padding: "8px 6px", color: "var(--color-severe)", fontWeight: 600 }}>At Risk</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border-color)" }}>
                    <td style={{ padding: "8px 6px", fontFamily: "var(--font-mono)" }}>SOC 2 CC6.3</td>
                    <td style={{ padding: "8px 6px" }}>Workforce Authentication & Key Management</td>
                    <td style={{ padding: "8px 6px" }}>INT-01, INT-02, IAM-01</td>
                    <td style={{ padding: "8px 6px", color: "var(--color-medium)", fontWeight: 600 }}>Remediation Required</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border-color)" }}>
                    <td style={{ padding: "8px 6px", fontFamily: "var(--font-mono)" }}>ISO 27001 A.12</td>
                    <td style={{ padding: "8px 6px" }}>Operations Security & Malware Protection</td>
                    <td style={{ padding: "8px 6px" }}>MCH-02, MCH-04</td>
                    <td style={{ padding: "8px 6px", color: "var(--color-positive)", fontWeight: 600 }}>Remediable in Sprint</td>
                  </tr>
                  <tr>
                    <td style={{ padding: "8px 6px", fontFamily: "var(--font-mono)" }}>NIST CSF PR.AC</td>
                    <td style={{ padding: "8px 6px" }}>Access Control & Identity Assurance</td>
                    <td style={{ padding: "8px 6px" }}>INT-04, INT-05</td>
                    <td style={{ padding: "8px 6px", color: "var(--color-positive)", fontWeight: 600 }}>Compliant with Policy</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div style={{ textAlign: "right", marginTop: "16px" }}>
              <button
                type="button"
                className="btn-file-select"
                onClick={() => setShowComplianceModal(false)}
              >
                CLOSE COMPLIANCE MATRIX
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
