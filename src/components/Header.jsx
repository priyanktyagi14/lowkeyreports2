import React, { useState, useEffect } from "react";
import { checkLayaHealth } from "../utils/vulnerabilityFetcher";

export function Header({ currentView, onReset }) {
  const [health, setHealth] = useState({
    checking: true,
    ready: false,
    status: "checking",
    latencyMs: null
  });

  const checkStatus = async () => {
    setHealth((prev) => ({ ...prev, checking: true }));
    const t0 = performance.now();
    try {
      const res = await checkLayaHealth();
      const latency = Math.round(performance.now() - t0);
      setHealth({
        checking: false,
        ready: Boolean(res && res.ready),
        status: res && res.ready ? "online" : "offline",
        latencyMs: latency
      });
    } catch {
      setHealth({
        checking: false,
        ready: false,
        status: "offline",
        latencyMs: null
      });
    }
  };

  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 25000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="site-header">
      <div className="brand-block">
        <div className="brand-badge">LOWKEYREPORTS</div>
        <div>
          <h1 className="brand-title">LOWKEYREPORTS</h1>
          <div className="brand-subtitle">Telemetry-to-Dollar Financial Actuarial Engine</div>
        </div>
      </div>

      <div className="header-actions">
        <div
          className={`model-badge ${health.ready ? "is-online" : "is-fallback"}`}
          onClick={checkStatus}
          title={
            health.ready
              ? `Local Laya AI Core is ONLINE on port 8000 (${health.latencyMs}ms latency). Click to re-check.`
              : "Local Laya service is offline. Using calibrated Open FAIR baseline. Run 'npm run start:laya' to start. Click to re-check."
          }
          style={{ cursor: "pointer" }}
        >
          <span
            className="status-pip"
            style={{
              background: health.checking
                ? "var(--color-medium)"
                : health.ready
                ? "#22c55e"
                : "#eab308"
            }}
          ></span>
          <span>
            {health.checking
              ? "CONNECTING LAYA..."
              : health.ready
              ? `LOCAL LAYA AI (ONLINE · ${health.latencyMs}ms)`
              : "LOCAL LAYA AI (STANDBY / BASELINE)"}
          </span>
        </div>

        {currentView === "dashboard" && (
          <button
            type="button"
            className="btn-secondary-action"
            onClick={onReset}
          >
            ← INGEST NEW ARCHIVE (.ZIP)
          </button>
        )}
      </div>
    </header>
  );
}
