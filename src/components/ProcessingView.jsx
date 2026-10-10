import React, { useEffect, useState, useRef } from "react";
import { extractZipTelemetry } from "../utils/zipParser";
import { fetchVulnerabilities } from "../utils/vulnerabilityFetcher";
import { DEFAULT_VULNERABILITIES, computeQuantificationSummary, formatCurrency } from "../data/telemetryData";

export function ProcessingView({ parsedData, onComplete }) {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [logs, setLogs] = useState([
    `[LAYA-AI-LOCAL] Telemetry bundle received: "${parsedData.filename || 'bundle.zip'}"`,
    `[LAYA-AI-LOCAL] Initializing Local Laya Decision Core (convaiinnovations/laya)...`
  ]);
  const hasStartedRef = useRef(false);

  const steps = [
    { title: "Manifest & Telemetry Extraction", desc: "Decompressing archive & extracting anomalies from SIEM, EDR, and IAM feeds" },
    { title: "Actuarial Exposure Modeling", desc: "Evaluating Threat Event Frequency (TEF) & Single Loss Expectancy (SLE) via Local Laya AI" },
    { title: "Capital Cost & ROI Delta", desc: "Evaluating remediation engineering spend vs unmitigated loss" },
    { title: "Board Risk Triage & Synthesis", desc: "Partitioning findings into Severe, Medium, and Ignorable categories" }
  ];

  useEffect(() => {
    if (hasStartedRef.current) return;
    hasStartedRef.current = true;

    async function runPipeline() {
      try {
        let extracted = parsedData;
        let dynamicVulns = parsedData.vulnerabilities;

        // Step 1: Manifest & Log Extraction
        if (parsedData.file) {
          setLogs((prev) => [
            ...prev,
            `[EXTRACT] Reading archive structure and uncompressing telemetry streams...`
          ]);

          extracted = await extractZipTelemetry(parsedData.file);

          const highlights = extracted.logHighlights || [];
          setLogs((prev) => [
            ...prev,
            `[MANIFEST] Unpacked ${extracted.fileCount} telemetry files:`,
            `  • SIEM Telemetry: ${extracted.detectedSources.siem ? "CONFIRMED" : "NOT DETECTED"}`,
            `  • EDR Telemetry: ${extracted.detectedSources.edr ? "CONFIRMED" : "NOT DETECTED"}`,
            `  • IAM Identity Matrix: ${extracted.detectedSources.iam ? "CONFIRMED" : "NOT DETECTED"}`,
            ...(highlights.length > 0 ? highlights.map((h) => `  ↳ ${h}`) : []),
            `[ANOMALIES] Extracted ${extracted.rawFindings.length} candidate telemetry anomalies for AI evaluation.`
          ]);
        }

        // Advance to Step 2: Laya AI Actuarial Modeling
        await new Promise((r) => setTimeout(r, 600));
        setCurrentStepIndex(1);

        if (!dynamicVulns) {
          if (extracted.customVulnerabilities) {
            dynamicVulns = extracted.customVulnerabilities;
            setLogs((prev) => [
              ...prev,
              `[CUSTOM-OVERRIDE] Loaded pre-calibrated risk findings from bundle override.`
            ]);
          } else {
            setLogs((prev) => [
              ...prev,
              `[LAYA-AI] Forwarding findings to Local Laya Decision Core (port 8000)...`,
              `[LAYA-AI] Executing non-autoregressive forward-pass classification across threat domains...`
            ]);

            const t0 = performance.now();
            dynamicVulns = await fetchVulnerabilities({
              filename: extracted.filename || "bundle.zip",
              fileCount: extracted.fileCount || 0,
              fileDetails: extracted.fileDetails || [],
              detectedSources: extracted.detectedSources,
              rawFindings: extracted.rawFindings || []
            });
            const elapsed = Math.round(performance.now() - t0);

            setLogs((prev) => [
              ...prev,
              `[LAYA-AI] Successfully classified ${dynamicVulns.length} vulnerabilities in ${elapsed}ms.`
            ]);
          }
        }

        // Advance to Step 3: Capital Cost & ROI Delta
        await new Promise((r) => setTimeout(r, 600));
        setCurrentStepIndex(2);

        const summary = computeQuantificationSummary(dynamicVulns || DEFAULT_VULNERABILITIES);
        setLogs((prev) => [
          ...prev,
          `[FIN-CRQ] Calibrating FAIR loss metrics: Total Unmitigated Exposure = ${formatCurrency(summary.totalLoss)}`,
          `[FIN-CRQ] Planned Engineering Remediation Spend = ${formatCurrency(summary.totalCost)}`,
          `[FIN-CRQ] Preserved Balance Sheet Capital = +${formatCurrency(summary.netSavings)}`
        ]);

        // Advance to Step 4: Board Risk Triage & Synthesis
        await new Promise((r) => setTimeout(r, 600));
        setCurrentStepIndex(3);
        setLogs((prev) => [
          ...prev,
          `[SYNTHESIS] Categorization complete: ${summary.severeCount} Severe | ${summary.mediumCount} Medium | ${summary.ignorableCount} Ignorable (Negative ROI)`,
          `[SYNTHESIS] Executive dossiers compiled. Initializing Board Quantifier Ledger...`
        ]);

        await new Promise((r) => setTimeout(r, 700));
        onComplete({
          ...extracted,
          vulnerabilities: dynamicVulns || DEFAULT_VULNERABILITIES
        });
      } catch (err) {
        console.error("Processing pipeline error:", err);
        setLogs((prev) => [
          ...prev,
          `[ERROR] Exception encountered during processing: ${err.message || err}`,
          `[FALLBACK] Initializing baseline Open FAIR actuarial dataset...`
        ]);
        await new Promise((r) => setTimeout(r, 800));
        onComplete({
          ...parsedData,
          vulnerabilities: DEFAULT_VULNERABILITIES
        });
      }
    }

    runPipeline();
  }, []);

  return (
    <div className="processing-container">
      <div className="processing-header">
        <div>
          <h2 className="processing-title">Actuarial Cyber Risk Modeling</h2>
          <div className="processing-sub">ENGINE: LOCAL LAYA DECISION CORE (0.4.1)</div>
        </div>
        <div className="model-badge">
          <span className="status-pip" style={{ background: "var(--color-medium)" }}></span>
          <span>PROCESSING TELEMETRY</span>
        </div>
      </div>

      <div className="pipeline-steps">
        {steps.map((step, idx) => {
          let statusClass = "pending";
          if (idx < currentStepIndex) statusClass = "completed";
          else if (idx === currentStepIndex) statusClass = "active";

          return (
            <div key={idx} className={`step-row ${statusClass}`}>
              <div className="step-indicator">
                {idx < currentStepIndex ? "✓" : idx + 1}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>{step.title}</div>
                <div style={{ fontSize: "11px", color: "var(--text-tertiary)" }}>{step.desc}</div>
              </div>
              <div style={{ fontSize: "10px", color: "var(--text-secondary)" }}>
                {idx < currentStepIndex ? "COMPLETE" : idx === currentStepIndex ? "CALCULATING..." : "QUEUED"}
              </div>
            </div>
          );
        })}
      </div>

      <div className="terminal-box" style={{ maxHeight: "240px", overflowY: "auto" }}>
        {logs.map((log, i) => (
          <div key={i}>{log}</div>
        ))}
      </div>
    </div>
  );
}
