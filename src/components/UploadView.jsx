import React, { useState, useRef } from "react";
import { generateSampleZipBundle } from "../utils/zipParser";

export function UploadView({ onStartProcessing, companyName, setCompanyName }) {
  const [isDragging, setIsDragging] = useState(false);
  const [isLoadingSample, setIsLoadingSample] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const fileInputRef = useRef(null);

  const handleFile = async (file) => {
    if (!file) return;
    setErrorMsg(null);

    if (!file.name.toLowerCase().endsWith(".zip")) {
      setErrorMsg("Please upload a single .zip archive containing SIEM + EDR + IAM telemetry data.");
      return;
    }

    onStartProcessing({
      file,
      filename: file.name,
      companyName: companyName || "Acme Global Enterprise"
    });
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleLoadSample = async () => {
    setIsLoadingSample(true);
    setErrorMsg(null);
    try {
      const sampleZipFile = await generateSampleZipBundle();
      onStartProcessing({
        file: sampleZipFile,
        filename: sampleZipFile.name,
        companyName: companyName || "Acme Global Enterprise"
      });
    } catch (err) {
      console.error("Sample generation error:", err);
      setErrorMsg("Failed to generate test bundle.");
    } finally {
      setIsLoadingSample(false);
    }
  };

  const handleDownloadSampleZip = async () => {
    try {
      const sampleZipFile = await generateSampleZipBundle();
      const url = URL.createObjectURL(sampleZipFile);
      const a = document.createElement("a");
      a.href = url;
      a.download = "sample_telemetry_siem_edr_iam.zip";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download error:", err);
    }
  };

  return (
    <div className="upload-view">
      <div className="upload-lead">
        <h2 className="upload-headline">Translate Cyber Telemetry into Board-Level Financial Decisions</h2>
        <p className="upload-subheadline">
          Upload a single <code>.zip</code> bundle containing your enterprise SIEM event logs, EDR endpoint telemetry, and IAM identity configurations. Local Laya AI models dollar-loss exposure against targeted remediation capital.
        </p>
      </div>

      <div className="upload-instruction-grid">
        <div className="instruction-box">
          <div className="instruction-tag">STREAM 01 // TELEMETRY</div>
          <div className="instruction-title">SIEM Event Logs</div>
          <div className="instruction-desc">
            Splunk, QRadar, or Elastic JSON/log exports. Quantifies anomaly frequency and alert escalation rate.
          </div>
        </div>

        <div className="instruction-box">
          <div className="instruction-tag">STREAM 02 // ENDPOINTS</div>
          <div className="instruction-title">EDR Agent State</div>
          <div className="instruction-desc">
            CrowdStrike, SentinelOne, or Defender exports. Maps unpatched CVEs, host isolations, and root access.
          </div>
        </div>

        <div className="instruction-box">
          <div className="instruction-tag">STREAM 03 // IDENTITIES</div>
          <div className="instruction-title">IAM Matrix</div>
          <div className="instruction-desc">
            Okta, Azure AD, or AWS IAM exports. Assesses hardcoded keys, stale contractor sessions, and MFA hygiene.
          </div>
        </div>
      </div>

      {/* Target Entity Branding Field */}
      <div className="enterprise-input-row" style={{
        margin: "24px 0 16px 0",
        padding: "16px 20px",
        background: "var(--bg-card)",
        border: "1px solid var(--border-color)",
        borderRadius: "2px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "20px"
      }}>
        <div style={{ flex: 1 }}>
          <label style={{
            display: "block",
            fontSize: "11px",
            fontFamily: "var(--font-mono)",
            color: "var(--text-tertiary)",
            marginBottom: "6px",
            letterSpacing: "0.06em"
          }}>
            BOARD AUDIT TARGET // ENTERPRISE / COMPANY NAME
          </label>
          <input
            type="text"
            value={companyName}
            onChange={(e) => setCompanyName && setCompanyName(e.target.value)}
            placeholder="e.g. Acme Global Enterprise"
            style={{
              width: "100%",
              maxWidth: "420px",
              background: "var(--bg-main)",
              border: "1px solid var(--border-strong)",
              color: "var(--text-primary)",
              padding: "8px 12px",
              fontFamily: "var(--font-sans)",
              fontSize: "14px",
              borderRadius: "2px",
              outline: "none"
            }}
          />
        </div>
        <div style={{
          fontSize: "11px",
          color: "var(--text-secondary)",
          maxWidth: "340px",
          lineHeight: "1.4"
        }}>
          This entity name will appear on all executive board PDF dossiers, single-page risk briefs, and statutory SEC filings.
        </div>
      </div>

      <div
        className={`dropzone-container ${isDragging ? "is-dragging" : ""}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current && fileInputRef.current.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".zip"
          style={{ display: "none" }}
          onChange={(e) => {
            if (e.target.files && e.target.files.length > 0) {
              handleFile(e.target.files[0]);
            }
          }}
        />

        <div className="dropzone-icon-row">
          <div className="dropzone-icon-box">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
          </div>
        </div>

        <div className="dropzone-main-text">Drop your telemetry archive here (.zip)</div>
        <div className="dropzone-sub-text">Must contain SIEM, EDR, and IAM exports in a single compressed archive</div>

        <button
          type="button"
          className="btn-file-select"
          onClick={(e) => {
            e.stopPropagation();
            fileInputRef.current && fileInputRef.current.click();
          }}
        >
          SELECT .ZIP FILE
        </button>
      </div>

      {errorMsg && (
        <div
          style={{
            background: "var(--color-severe-bg)",
            border: "1px solid var(--color-severe-border)",
            color: "var(--color-severe)",
            padding: "12px 16px",
            fontFamily: "var(--font-mono)",
            fontSize: "12px",
            marginBottom: "20px",
            borderRadius: "2px"
          }}
        >
          [ERROR] {errorMsg}
        </div>
      )}

      <div className="upload-actions-row">
        <div className="sample-notice">
          Don't have enterprise telemetry files readily available?
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            type="button"
            className="btn-load-sample"
            onClick={handleDownloadSampleZip}
            title="Download the realistic synthetic .zip file to inspect its contents"
          >
            DOWNLOAD TEST .ZIP
          </button>
          <button
            type="button"
            className="btn-load-sample"
            onClick={handleLoadSample}
            disabled={isLoadingSample}
          >
            {isLoadingSample ? "GENERATING BUNDLE..." : "RUN DEMO BUNDLE (.ZIP)"}
          </button>
        </div>
      </div>
    </div>
  );
}
