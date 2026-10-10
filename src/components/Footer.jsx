import React from "react";

export function Footer() {
  return (
    <footer className="site-footer">
      <div className="footer-inner">
        <div className="footer-left">
          <strong>LOWKEYREPORTS</strong>
          <p>
            Statistical loss modeling powered by Local Laya AI (convaiinnovations/laya). Based on the Open FAIR standard (Factor Analysis of Information Risk - ANSI/O-RA).
          </p>
        </div>

        <div className="footer-right">
          <div className="footer-pill">INGEST: SIEM + EDR + IAM</div>
          <div className="footer-pill">SEC 10-K READY</div>
          <div className="footer-pill">ISO 27005 / NIST 800-30</div>
        </div>
      </div>
    </footer>
  );
}
