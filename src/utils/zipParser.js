import JSZip from "jszip";
import { fetchVulnerabilities } from "./vulnerabilityFetcher.js";
import { DEFAULT_VULNERABILITIES } from "../data/telemetryData.js";

/**
 * Parses simple CSV content into an array of objects.
 */
function parseSimpleCsv(text) {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map((h) => h.trim().replace(/^["']|["']$/g, ""));
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(",").map((c) => c.trim().replace(/^["']|["']$/g, ""));
    const row = {};
    headers.forEach((h, idx) => {
      row[h] = cols[idx] !== undefined ? cols[idx] : "";
    });
    rows.push(row);
  }
  return rows;
}

/**
 * Extracts metadata, log files, and actual telemetry anomalies from an uploaded zip.
 * Fast asynchronous decompression that does NOT execute Laya API yet.
 */
export async function extractZipTelemetry(file) {
  const zip = new JSZip();
  const loadedZip = await zip.loadAsync(file);

  const filenames = Object.keys(loadedZip.files);
  const detectedSources = {
    siem: false,
    edr: false,
    iam: false
  };

  const fileDetails = [];
  const rawFindings = [];
  const logHighlights = [];

  for (const filename of filenames) {
    const entry = loadedZip.files[filename];
    if (entry.dir) continue;

    const lower = filename.toLowerCase();
    let sourceType = "Unknown";

    // 1. SIEM Event Logs Extraction
    if (lower.includes("siem") || lower.includes("splunk") || lower.includes("qradar") || lower.includes("elastic")) {
      detectedSources.siem = true;
      sourceType = "SIEM Telemetry";
      try {
        const content = await entry.async("text");
        if (lower.endsWith(".json")) {
          const siemJson = JSON.parse(content);
          if (Array.isArray(siemJson.critical_alerts)) {
            siemJson.critical_alerts.forEach((alt, idx) => {
              rawFindings.push({
                id: alt.id || `SIEM-AL-${idx + 1}`,
                name: alt.rule || alt.name || "SIEM Critical Security Anomaly",
                targetGroup: "Production Ingress & Cloud Perimeter",
                source: "SIEM",
                threatActor: "Automated Recon & Exploitation Threat Actor",
                attackVector: "T1190 - Exploit Public-Facing Application",
                cveList: "CWE-287 Improper Authentication",
                complianceImpact: "SOC 2 Type II CC6.1, ISO 27001 Annex A.12",
                annualProbability: "85% Annualized Likelihood",
                lossIfIgnored: alt.severity === "CRITICAL" ? 1150000 : 420000,
                solutionCost: 16000,
                lossBreakdown: `Breach containment & forensics for rule alert (${alt.count || 1} hits)`,
                technicalFinding: `Alert "${alt.rule || alt.name}" triggered ${alt.count || 1} times with ${alt.severity || "HIGH"} severity in SIEM logs.`,
                businessImpact: "Risk of unauthenticated ingress breach, data leakage, and service disruption.",
                solutionPlan: "Phase 1: Rate limit source subnets. Phase 2: Rotate perimeter credentials. Phase 3: Update WAF/SIEM correlation rules."
              });
            });
            logHighlights.push(`SIEM: Extracted ${siemJson.critical_alerts.length} critical alert findings from ${filename}`);
          }
        }
      } catch (err) {
        console.warn(`Failed parsing SIEM file ${filename}:`, err);
      }
    }

    // 2. EDR Telemetry Extraction
    if (lower.includes("edr") || lower.includes("crowdstrike") || lower.includes("sentinel") || lower.includes("endpoint")) {
      detectedSources.edr = true;
      sourceType = "EDR Telemetry";
      try {
        const content = await entry.async("text");
        if (lower.endsWith(".csv")) {
          const rows = parseSimpleCsv(content);
          const isolated = rows.filter((r) =>
            String(r.EDRIsolationTriggered).toLowerCase() === "true" ||
            (r.CriticalCVECount && r.CriticalCVECount !== "None")
          );
          isolated.forEach((row, idx) => {
            rawFindings.push({
              id: row.AgentID || `EDR-AG-${idx + 1}`,
              name: `EDR Endpoint Alert: ${row.Hostname || "Isolated Host"} (${row.CriticalCVECount || "Vulnerability"})`,
              targetGroup: `Workstations & Ingress Nodes (${row.OS || "Linux"})`,
              source: "EDR",
              threatActor: "APT Group & Ransomware Operators",
              attackVector: "T1068 - Exploitation for Privilege Escalation",
              cveList: row.CriticalCVECount && row.CriticalCVECount !== "None" ? row.CriticalCVECount : "CVE-2024-7646",
              complianceImpact: "PCI-DSS 6.2, NIST CSF PR.IP-12",
              annualProbability: "78% Annualized Likelihood",
              lossIfIgnored: 980000,
              solutionCost: 19000,
              lossBreakdown: "Host recovery, forensic agent isolation, patch deployment engineering",
              technicalFinding: `EDR Agent ${row.AgentID || idx} on ${row.Hostname} reported isolation status: ${row.EDRIsolationTriggered}. Kernel: ${row.KernelVersion || "N/A"}.`,
              businessImpact: "Host privilege escalation, ransomware foothold, or unpatched kernel exploitation.",
              solutionPlan: "Phase 1: Maintain network isolation. Phase 2: Deploy kernel vulnerability patch. Phase 3: Validate EDR agent health."
            });
          });
          logHighlights.push(`EDR: Extracted ${isolated.length} host isolation & CVE alerts from ${filename}`);
        }
      } catch (err) {
        console.warn(`Failed parsing EDR file ${filename}:`, err);
      }
    }

    // 3. IAM Identity Matrix Extraction
    if (lower.includes("iam") || lower.includes("okta") || lower.includes("azuread") || lower.includes("access") || lower.includes("identity")) {
      detectedSources.iam = true;
      sourceType = "IAM Telemetry";
      try {
        const content = await entry.async("text");
        if (lower.endsWith(".json")) {
          const iamJson = JSON.parse(content);
          if (Array.isArray(iamJson.issues)) {
            iamJson.issues.forEach((iss, idx) => {
              rawFindings.push({
                id: `IAM-RSK-${idx + 1}`,
                name: `IAM Identity Defect: ${iss.role || "Entitlement"}`,
                targetGroup: "IAM Principals & Service Roles",
                source: "IAM",
                threatActor: "Credential Stuffers & Rogue Insiders",
                attackVector: "T1078.004 - Cloud Accounts",
                cveList: "CWE-798 Hardcoded Credentials / Stale Access",
                complianceImpact: "SOC 2 Type II CC6.3, ISO 27001 A.9.2",
                annualProbability: "80% Annualized Likelihood",
                lossIfIgnored: iss.risk === "CRITICAL" ? 1250000 : 450000,
                solutionCost: 12000,
                lossBreakdown: "Account takeover incident costs, forensic token revocations",
                technicalFinding: `${iss.role || "Principal"}: ${iss.issue} (Risk severity: ${iss.risk || "HIGH"}).`,
                businessImpact: "Stale session hijacking, unauthorized admin actions, audit control failure.",
                solutionPlan: "Phase 1: Invalidate active tokens. Phase 2: Prune overprivileged permissions. Phase 3: Mandate phishing-resistant MFA."
              });
            });
            logHighlights.push(`IAM: Extracted ${iamJson.issues.length} identity & privilege issues from ${filename}`);
          }
        }
      } catch (err) {
        console.warn(`Failed parsing IAM file ${filename}:`, err);
      }
    }

    fileDetails.push({
      name: filename,
      size: entry._data ? (entry._data.uncompressedSize || 1024) : 1024,
      sourceType
    });
  }

  // Check for custom override JSON if present
  let customVulnerabilities = null;
  const vulnFile = filenames.find(
    (f) => f.toLowerCase().endsWith("vulnerabilities.json") || f.toLowerCase().endsWith("quantified_risks.json")
  );
  if (vulnFile) {
    try {
      const text = await loadedZip.files[vulnFile].async("text");
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed) && parsed.length > 0) {
        customVulnerabilities = parsed;
        logHighlights.push(`Custom: Found pre-calibrated vulnerability ledger in ${vulnFile}`);
      }
    } catch {
      // ignore
    }
  }

  return {
    filename: file.name,
    fileCount: fileDetails.length,
    fileDetails,
    detectedSources,
    rawFindings,
    customVulnerabilities,
    logHighlights
  };
}

/**
 * End-to-end telemetry parser: extracts manifest and then calls Local Laya AI to quantify vulnerabilities.
 */
export async function parseTelemetryZip(file) {
  const extracted = await extractZipTelemetry(file);

  let dynamicVulnerabilities = extracted.customVulnerabilities;
  if (!dynamicVulnerabilities) {
    try {
      dynamicVulnerabilities = await fetchVulnerabilities({
        filename: extracted.filename,
        fileCount: extracted.fileCount,
        fileDetails: extracted.fileDetails,
        detectedSources: extracted.detectedSources,
        rawFindings: extracted.rawFindings
      });
    } catch (err) {
      console.warn("[parseTelemetryZip] Fetching vulnerabilities failed, using default baseline.", err);
      dynamicVulnerabilities = DEFAULT_VULNERABILITIES;
    }
  }

  return {
    ...extracted,
    vulnerabilities: dynamicVulnerabilities || DEFAULT_VULNERABILITIES
  };
}

/**
 * Creates a synthetic realistic sample telemetry .zip archive containing SIEM, EDR, and IAM files.
 * Allows instant testing or direct download of a valid test bundle.
 */
export async function generateSampleZipBundle() {
  const zip = new JSZip();

  // 1. SIEM event log
  const siemData = {
    collector: "SIEM_INGEST_AGENT_V4",
    time_window: "Last 30 Days",
    total_events: 18420950,
    anomalies_detected: 48,
    critical_alerts: [
      { id: "SIEM-AL-901", rule: "Repeated S3 Public Bucket Policy Changes", severity: "HIGH", count: 14 },
      { id: "SIEM-AL-904", rule: "Authentication Brute Force against /v2/auth/token", severity: "CRITICAL", count: 421000 },
      { id: "SIEM-AL-922", rule: "Inbound SSH Port Sweep to Bastion 0.0.0.0/0", severity: "CRITICAL", count: 9140 },
      { id: "SIEM-AL-930", rule: "Unverified Webhook Invocations without HMAC Header", severity: "MEDIUM", count: 83 }
    ]
  };
  zip.file("siem_telemetry_events.json", JSON.stringify(siemData, null, 2));

  // 2. EDR telemetry CSV
  const edrCsv = [
    "AgentID,Hostname,OS,KernelVersion,AgentStatus,CriticalCVECount,EDRIsolationTriggered",
    "EDR-US-01,prod-k8s-ingress-node-01,Ubuntu 22.04 LTS,5.15.0-101,Active,CVE-2024-7646,true",
    "EDR-US-02,prod-k8s-ingress-node-02,Ubuntu 22.04 LTS,5.15.0-101,Active,CVE-2024-7646,true",
    "EDR-EU-01,db-aurora-bastion-gateway,Amazon Linux 2023,6.1.72,Active,CVE-2023-4806,false",
    "EDR-WORK-14,macbook-eng-sarah-m2,macOS 14.1,Darwin 23.1,Active,None (FileVault Disabled),false",
    "EDR-WORK-29,dell-fin-payroll-03,Windows 11 Ent,10.0.22631,Active,None (SMS MFA Only),false"
  ].join("\n");
  zip.file("edr_endpoint_telemetry.csv", edrCsv);

  // 3. IAM permissions matrix
  const iamData = {
    provider: "Okta + AWS IAM Identity Center",
    total_principals: 342,
    service_accounts: 88,
    overprivileged_roles: 12,
    issues: [
      { role: "DeveloperAdminAccess", issue: "Unrotated AWS API Keys hardcoded in git commit history", risk: "CRITICAL" },
      { role: "VendorContractorRole", issue: "14 inactive contractors still have SAML session entitlement", risk: "HIGH" },
      { role: "StagingServiceRole", issue: "Access to legacy mediawiki on 10.0.9.x", risk: "LOW" }
    ]
  };
  zip.file("iam_identity_matrix.json", JSON.stringify(iamData, null, 2));

  // 4. Manifest
  zip.file(
    "MANIFEST.txt",
    "CYBER TELEMETRY SUITE\nBundle Version: 2026.04\nContains: SIEM, EDR, IAM\nValidated for Local Laya AI Cyber Risk Quantification Processing."
  );

  const blob = await zip.generateAsync({ type: "blob" });
  return new File([blob], "telemetry_siem_edr_iam_bundle.zip", { type: "application/zip" });
}
