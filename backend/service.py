"""Local Laya AI Cyber Risk Quantification Service.

Provides local model inference using Laya (convaiinnovations/laya) for:
- Threat domain classification (internal / external / machines)
- Risk severity categorization (Severe / Medium / Ignorable)
- Actionable remediation prioritization
- Exploitability and compliance risk evaluation

Numerical loss and cost formulas remain deterministic according to
Open FAIR actuarial modeling principles.
"""

from contextlib import asynccontextmanager
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("laya_service")

# Global router instance
router_instance = None

# Laya Typed Question Definitions for Cyber Risk Quantification
CYBER_RISK_QUESTIONS = {
    "domain": {
        "type": "choice",
        "instructions": "Which enterprise risk domain does this vulnerability or threat finding belong to?",
        "criteria": {
            "internal": "Employees, developers, workstations, internal IAM credentials, payroll, staging secrets",
            "external": "Customers, public web portals, vendor APIs, supply chain, WAF ingress, cloud edge",
            "machines": "Servers, Kubernetes clusters, database bastions, microservices, cloud infrastructure"
        }
    },
    "severity": {
        "type": "choice",
        "instructions": "What is the actuarial severity and loss exposure category for this finding?",
        "criteria": {
            "Severe": "High unmitigated financial loss, active credential theft or remote exploit, critical priority",
            "Medium": "Substantial exposure, configuration hygiene deficit, positive remediation ROI",
            "Ignorable": "Minimal financial loss, isolated asset, negative ROI where engineering cost exceeds risk"
        }
    },
    "recommendation": {
        "type": "choice",
        "instructions": "What is the recommended financial remediation action priority?",
        "criteria": {
            "Immediate Remediation": "Urgent executive priority with high positive ROI",
            "Remediate in Sprint": "Address during standard engineering sprint with positive ROI",
            "Deprioritize / Accept Risk": "Negative ROI where solution cost exceeds financial exposure"
        }
    },
    "active_exploit": {
        "type": "noul",
        "instructions": "Is there evidence of active exploitation, unauthorized access, or credential abuse?"
    },
    "compliance_impact": {
        "type": "noul",
        "instructions": "Does this finding trigger regulatory or statutory audit compliance violations?"
    }
}

# Baseline enterprise vulnerability templates calibrated with FAIR actuarial metrics
CANDIDATE_VULNERABILITY_TEMPLATES = [
    # Internal People / Workforce / IAM
    {
        "id": "INT-01",
        "name": "Hardcoded Production Cloud Credentials in Git Repositories",
        "targetGroup": "Developers / DevOps",
        "source": "IAM + SIEM",
        "threatActor": "Nation-State APT & Automated Secret Scrapers",
        "attackVector": "T1552.001 - Credentials in Code Repositories",
        "cveList": "CWE-798 Hardcoded Credentials, CWE-522",
        "complianceImpact": "SOC 2 Type II CC6.1, SEC 4-Day Incident Rule, ISO 27001 A.9.4",
        "annualProbability": "82% Annualized Likelihood",
        "baseLoss": 1250000,
        "baseCost": 18000,
        "lossBreakdown": "Ransomware Extortion: $650K | Forensic Audit: $280K | Cloud Resource Theft: $320K",
        "technicalFinding": "4 engineers committed unmasked AWS_SECRET_ACCESS_KEY credentials to active feature branch repositories with root permissions.",
        "businessImpact": "Direct infrastructure takeover, crypto-mining hijacking, or proprietary code exfiltration causing $1.25M in downtime and liability.",
        "solutionPlan": "Phase 1: Invalidate leaked keys immediately and revoke active STS sessions. Phase 2: Deploy TruffleHog pre-commit git hooks. Phase 3: Enforce AWS IAM Identity Center temporary role assumption."
    },
    {
        "id": "INT-02",
        "name": "Finance Department Spearphishing & MFA Fatigue Susceptibility",
        "targetGroup": "Finance & Payroll Approvers",
        "source": "IAM + EDR",
        "threatActor": "FIN7 / Business Email Compromise (BEC) Cartels",
        "attackVector": "T1566.002 - Spearphishing Link & T1621 MFA Fatigue",
        "cveList": "CWE-308 Use of Implicit Intent for Authentication",
        "complianceImpact": "SOX 404 Internal Controls, GLBA Safeguards Rule, PCI-DSS v4.0",
        "annualProbability": "74% Annualized Likelihood",
        "baseLoss": 820000,
        "baseCost": 12000,
        "lossBreakdown": "Direct Wire Fraud: $520K | Forensic Legal Fees: $180K | Cyber Insurance Deductible: $120K",
        "technicalFinding": "18 finance personnel using SMS-based 2FA; SIEM logs show 3 credential brute-force anomalies from foreign IP subnets bypassing geolocation controls.",
        "businessImpact": "Wire fraud, payroll diversion, and executive impersonation with average recovery cost exceeding $820K.",
        "solutionPlan": "Phase 1: Disable legacy SMS MFA fallbacks across Okta/Entra. Phase 2: Issue YubiKey FIDO2 hardware keys to all payroll approvers. Phase 3: Implement dual-authorization verification for wire transfers over $25K."
    },
    {
        "id": "INT-03",
        "name": "Unsanctioned Consumer Generative AI Tool Ingestion of Sensitive IP",
        "targetGroup": "Product & Engineering Staff",
        "source": "EDR + SIEM",
        "threatActor": "Untrusted AI Vendors & Third-Party Training Harvesters",
        "attackVector": "T1567 - Exfiltration Over Web Service (Shadow AI)",
        "cveList": "OWASP Top 10 for LLM: LLM06 Sensitive Information Disclosure",
        "complianceImpact": "GDPR Article 32, EU AI Act, Customer NDA Agreements",
        "annualProbability": "68% Annualized Likelihood",
        "baseLoss": 340000,
        "baseCost": 25000,
        "lossBreakdown": "IP Invalidation & Litigation: $220K | Regulatory Fines: $80K | Customer Notifications: $40K",
        "technicalFinding": "EDR web-filtering logged 2,400+ clipboard pastes containing roadmap drafts and internal schema into unauthorized consumer AI tools.",
        "businessImpact": "Trade secret leakage, potential IP invalidation, and contractual non-disclosure breach risks.",
        "solutionPlan": "Phase 1: Block consumer AI endpoints via Cloudflare CASB/SWG. Phase 2: Provision enterprise-tier AI workspace licenses with zero-retention data isolation. Phase 3: Deliver mandatory IP security micro-training."
    },
    {
        "id": "INT-04",
        "name": "Developer Workstations with Disabled Disk Encryption & Root Privileges",
        "targetGroup": "Remote Engineering Staff",
        "source": "EDR",
        "threatActor": "Physical Device Thieves & Opportunistic Actors",
        "attackVector": "T1200 - Hardware Additions / Physical Access",
        "cveList": "CWE-311 Missing Encryption of Sensitive Data",
        "complianceImpact": "SOC 2 Type II CC6.6, HIPAA Security Rule §164.312",
        "annualProbability": "35% Annualized Likelihood",
        "baseLoss": 190000,
        "baseCost": 14000,
        "lossBreakdown": "Physical Asset Loss: $20K | Data Breach Audit: $110K | Token Invalidation: $60K",
        "technicalFinding": "12 developer laptops identified with local FileVault/BitLocker disabled and non-enforced screen timeout locks in remote worker locations.",
        "businessImpact": "Hardware theft leading to raw source code and local cookie token compromise ($190K forensic audit).",
        "solutionPlan": "Phase 1: Push non-bypassable FileVault2/BitLocker configuration profiles via MDM. Phase 2: Enforce 5-minute inactivity locks with biometric authentication. Phase 3: Enable automated remote wipe on 3 failed attempts."
    },
    {
        "id": "INT-05",
        "name": "Internal Staging Documentation Server Default Admin Credentials",
        "targetGroup": "Internal Wiki Users",
        "source": "IAM",
        "threatActor": "Internal Curious Staff / Non-Malicious Insider",
        "attackVector": "T1078.001 - Default Accounts on Isolated Host",
        "cveList": "CWE-255 Default Credentials",
        "complianceImpact": "Low Regulatory Exposure (No Customer Data, Isolated Intranet)",
        "annualProbability": "8% Annualized Likelihood",
        "baseLoss": 6000,
        "baseCost": 38000,
        "lossBreakdown": "Maximum cleanup cost: $6,000 internal IT hours",
        "technicalFinding": "Legacy staging MediaWiki on isolated RFC-1918 subnet retains default admin:admin password. Asset holds no customer data and is inaccessible externally.",
        "businessImpact": "Internal viewing of archived 2021 meeting notes. Maximum potential financial damage is under $6,000.",
        "solutionPlan": "Remediation quote involves contractor migration ($38,000). Actuarial analysis indicates spending $38,000 to protect a $6,000 isolated risk yields -84% ROI. Recommend accepting risk or decommissioning during next hardware cycle."
    },
    {
        "id": "INT-06",
        "name": "Developer Self-Signed Local Docker Registry Certificate Warning",
        "targetGroup": "Local Dev Sandbox",
        "source": "EDR",
        "threatActor": "None (Development Configuration)",
        "attackVector": "T1557 - Adversary-in-the-Middle (Theoretical)",
        "cveList": "CWE-295 Improper Certificate Validation",
        "complianceImpact": "None (Local loopback only)",
        "annualProbability": "3% Annualized Likelihood",
        "baseLoss": 4500,
        "baseCost": 22000,
        "lossBreakdown": "Internal engineer setup friction: $4,500",
        "technicalFinding": "Engineers run local Docker test registries using self-signed certs inside loopback 127.0.0.1. No external exposure.",
        "businessImpact": "Zero enterprise financial exposure. Fixing requires purchasing and managing local root CA certificates ($22,000).",
        "solutionPlan": "Accept risk as standard local developer environment behavior; add security exclusion to prevent scanner alert fatigue."
    },
    {
        "id": "INT-07",
        "name": "Overprivileged Cloud IAM Contractor Role Retention",
        "targetGroup": "Third-Party Contractors",
        "source": "IAM + SIEM",
        "threatActor": "Compromised Contractor Account / Rogue Contractor",
        "attackVector": "T1078.004 - Cloud Accounts",
        "cveList": "CWE-284 Improper Access Control",
        "complianceImpact": "SOC 2 Type II CC6.3, ISO 27001 A.9.2.6",
        "annualProbability": "58% Annualized Likelihood",
        "baseLoss": 410000,
        "baseCost": 15000,
        "lossBreakdown": "Unauthorized Data Export: $240K | Breach Assessment: $110K | Legal Counsel: $60K",
        "technicalFinding": "14 offboarded contractor accounts retained active SAML entitlements with AdministratorAccess in AWS development accounts.",
        "businessImpact": "Contractor breach leading to cloud infrastructure sabotage or data theft ($410K exposure).",
        "solutionPlan": "Phase 1: Automated sync between HRIS and IAM provider. Phase 2: Implement just-in-time (JIT) access policies with max 4-hour lifespan."
    },

    # External / Public Facing / Customer / Vendor
    {
        "id": "EXT-01",
        "name": "Public-Facing API Gateway Broken Object Level Authorization (BOLA)",
        "targetGroup": "Customer Mobile & Web API",
        "source": "SIEM + WAF",
        "threatActor": "Cybercriminal Syndicates & Bug Bounty Extortionists",
        "attackVector": "T1190 - Exploit Public-Facing Application",
        "cveList": "OWASP API Security Top 10: API1:2023 BOLA, CWE-639",
        "complianceImpact": "GDPR Article 33 (72h Notification), HIPAA §164.308, SEC Disclosure",
        "annualProbability": "88% Annualized Likelihood",
        "baseLoss": 2850000,
        "baseCost": 35000,
        "lossBreakdown": "Class-Action Defense: $1.2M | Regulatory Sanctions: $950K | PR & Notification: $700K",
        "technicalFinding": "Sequential integer IDs on /v2/customers/{id}/orders allow authenticated users to harvest complete order records of other tenants without authorization checks.",
        "businessImpact": "Systemic breach of 420,000 customer PII and payment history records, catastrophic brand erosion, and mandatory regulatory fines.",
        "solutionPlan": "Phase 1: Deploy WAF rate-limiting on tenant ID enumerations. Phase 2: Refactor API authorization middleware to assert cryptographically signed tenant ownership claims. Phase 3: Migrate all DB keys to random UUIDv4."
    },
    {
        "id": "EXT-02",
        "name": "Compromised Third-Party Analytics JavaScript Supply Chain Ingestion",
        "targetGroup": "Customer Checkout Flow",
        "source": "WAF + SIEM",
        "threatActor": "Magecart Group 8 / E-Commerce Skimming Cartels",
        "attackVector": "T1195.002 - Compromise Software Supply Chain",
        "cveList": "CWE-829 Inclusion of Functionality from Untrusted Sphere",
        "complianceImpact": "PCI-DSS v4.0 Requirement 6.4.3 & 11.6.1, CCPA Statutory Damages",
        "annualProbability": "62% Annualized Likelihood",
        "baseLoss": 1640000,
        "baseCost": 22000,
        "lossBreakdown": "Payment Card Reissuance Fines: $850K | Forensic PFI Audit: $450K | Merchant Surcharges: $340K",
        "technicalFinding": "Production checkout bundles load an unpinned external analytics script from a vendor CDN lacking Subresource Integrity (SRI) hashes.",
        "businessImpact": "Silent skimming of primary credit card account numbers (PAN) and CVV codes directly from customer browser sessions.",
        "solutionPlan": "Phase 1: Enforce Strict Content-Security-Policy (CSP) with script-src hashes. Phase 2: Implement automated SRI verification in CI/CD pipeline. Phase 3: Host all third-party dependencies on internal sandboxed CDN."
    },
    {
        "id": "EXT-03",
        "name": "Customer Authentication Portal Credential-Stuffing Vulnerability",
        "targetGroup": "Public Customer Accounts",
        "source": "WAF + SIEM",
        "threatActor": "Automated Credential-Stuffing Botnets",
        "attackVector": "T1110.004 - Credential Stuffing",
        "cveList": "CWE-307 Improper Restriction of Excessive Authentication Attempts",
        "complianceImpact": "FTC Consent Decree Risk, State Breach Notification Laws",
        "annualProbability": "79% Annualized Likelihood",
        "baseLoss": 480000,
        "baseCost": 16000,
        "lossBreakdown": "Account Takeover Remediation: $260K | Fraud Reimbursements: $140K | Support Escalations: $80K",
        "technicalFinding": "421,000 automated login attempts detected over 72 hours from rotating residential proxy IPs targeting the /v2/auth/login endpoint without CAPTCHA triggering.",
        "businessImpact": "Mass account takeovers, fraudulent loyalty point redemption, and elevated customer support costs.",
        "solutionPlan": "Phase 1: Enable Cloudflare bot management and adaptive rate-limiting. Phase 2: Integrate HaveIBeenPwned breached password screening on login. Phase 3: Mandate passkey/WebAuthn onboarding."
    },
    {
        "id": "EXT-04",
        "name": "Public Cloud Storage Bucket Permissive Read Permissions",
        "targetGroup": "Data Engineering S3 Buckets",
        "source": "SIEM + CloudTrail",
        "threatActor": "Opportunistic Cloud Data Scrapers",
        "attackVector": "T1530 - Data from Cloud Storage Object",
        "cveList": "CWE-732 Incorrect Permission Assignment for Critical Resource",
        "complianceImpact": "GDPR Article 32, SOC 2 Type II CC6.1",
        "annualProbability": "71% Annualized Likelihood",
        "baseLoss": 540000,
        "baseCost": 11000,
        "lossBreakdown": "Incident Response: $220K | Regulatory Notification: $180K | Customer Credits: $140K",
        "technicalFinding": "Anonymously readable S3 bucket policies detected containing anonymized batch processing artifacts and debugging logs.",
        "businessImpact": "Public disclosure of internal system telemetry and potential accidental disclosure of customer metadata.",
        "solutionPlan": "Phase 1: Enable AWS S3 Block Public Access at the AWS Organization level. Phase 2: Deploy AWS Config auto-remediation rule to revert public ACLs. Phase 3: Audit bucket lifecycle policies."
    },
    {
        "id": "EXT-05",
        "name": "Decommissioned Marketing Landing Page Subdomain Takeover Risk",
        "targetGroup": "Legacy DNS Records",
        "source": "DNS / SIEM",
        "threatActor": "Low-Skilled Bug Bounty Hunters / Spammers",
        "attackVector": "T1584.001 - DNS Hijacking (Dangling CNAME)",
        "cveList": "CWE-284 Dangling DNS Pointer",
        "complianceImpact": "Low Statutory Risk (No Backend Credentials Present)",
        "annualProbability": "12% Annualized Likelihood",
        "baseLoss": 8500,
        "baseCost": 29000,
        "lossBreakdown": "Reputational cleanup & DNS purge: $8,500",
        "technicalFinding": "Dangling CNAME promo2022.example.com points to an unclaimed Azure Blob storage container. Zero customer cookies or sensitive headers pass through this domain.",
        "businessImpact": "Defacement of an isolated promotional landing page. Maximum expected cleanup cost is under $8,500.",
        "solutionPlan": "Full enterprise automated DNS continuous verification suite vendor quote is $29,000/yr. Cost exceeds financial risk by 3.4x (-71% ROI). Recommend manually deleting the single dangling CNAME record without purchasing expensive tooling."
    },
    {
        "id": "EXT-06",
        "name": "Public Marketing Blog Verbose Apache Server Header Banner",
        "targetGroup": "Public Web Presence",
        "source": "WAF",
        "threatActor": "Automated Port Scanners (Shodan / Censys)",
        "attackVector": "T1592 - Gather Victim Host Information",
        "cveList": "CWE-200 Information Exposure",
        "complianceImpact": "None (Information disclosure only)",
        "annualProbability": "5% Annualized Likelihood",
        "baseLoss": 2500,
        "baseCost": 15000,
        "lossBreakdown": "Advisory review cost: $2,500",
        "technicalFinding": "Public blog server returns 'Server: Apache/2.4.52 (Ubuntu)' HTTP header on root URL responses.",
        "businessImpact": "Theoretical banner grabbing. Server is already behind Cloudflare and patched against known vulnerabilities.",
        "solutionPlan": "Deprioritize finding. Spending engineering consulting hours ($15,000) to strip the header produces negative financial ROI."
    },
    {
        "id": "EXT-07",
        "name": "Third-Party SaaS Integration Webhook Insecure Verification",
        "targetGroup": "Integration Microservices",
        "source": "SIEM + WAF",
        "threatActor": "Malicious Webhook Replay Adversaries",
        "attackVector": "T1565.001 - Data Manipulation",
        "cveList": "CWE-345 Insufficient Verification of Data Authenticity",
        "complianceImpact": "SOC 2 Type II CC6.8",
        "annualProbability": "44% Annualized Likelihood",
        "baseLoss": 275000,
        "baseCost": 14000,
        "lossBreakdown": "Fraudulent Order Reversals: $160K | Database Sanitization: $75K | Audit Hours: $40K",
        "technicalFinding": "Inbound billing webhook handler fails to verify cryptographic HMAC-SHA256 signature headers on incoming callback payloads.",
        "businessImpact": "Adversary can spoof fake payment successful webhooks to unlock digital premium entitlements.",
        "solutionPlan": "Phase 1: Enforce mandatory HMAC signature validation on all incoming webhooks. Phase 2: Add replay protection using nonce and timestamp verification within a 5-minute window."
    },

    # Machines / Infrastructure / Bastions / Kubernetes
    {
        "id": "MCH-01",
        "name": "Production Ingress Controller Remote Code Execution Vulnerability",
        "targetGroup": "Production Kubernetes Clusters",
        "source": "EDR + SIEM",
        "threatActor": "Ransomware Cartels (e.g., LockBit 3.0, BlackCat)",
        "attackVector": "T1190 - Exploit Public-Facing Application (Nginx Ingress)",
        "cveList": "CVE-2024-7646, CWE-94 Code Injection",
        "complianceImpact": "SEC 4-Day Incident Rule, PCI-DSS v4.0 Req 6.3, HIPAA Security Rule",
        "annualProbability": "91% Annualized Likelihood",
        "baseLoss": 3200000,
        "baseCost": 28000,
        "lossBreakdown": "Full Cluster Downtime: $1.8M | Ransomware Mitigation: $850K | Forensic Audit: $550K",
        "technicalFinding": "EDR detected active memory corruption and unvalidated annotation injection vulnerabilities across 8 production Ingress-Nginx pods allowing complete cluster takeover.",
        "businessImpact": "Total production outage, cryptographic extortion, and operational blackout across core revenue services.",
        "solutionPlan": "Phase 1: Patch Ingress-Nginx controllers to version v1.11.2+ immediately in rolling deployment. Phase 2: Enforce admission controllers blocking invalid ingress annotations. Phase 3: Segment worker nodes into isolated network namespaces."
    },
    {
        "id": "MCH-02",
        "name": "Core Financial Database Bastion Public SSH Port Exposure",
        "targetGroup": "Database Infrastructure Bastion",
        "source": "SIEM + EDR",
        "threatActor": "Nation-State APT29 & Automated Botnets",
        "attackVector": "T1021.004 - SSH Lateral Movement",
        "cveList": "CWE-1188 Insecure Default Initialization of Resource",
        "complianceImpact": "PCI-DSS v4.0 Req 1.3 & 2.2, SOC 2 CC6.6",
        "annualProbability": "86% Annualized Likelihood",
        "baseLoss": 2100000,
        "baseCost": 19000,
        "lossBreakdown": "DB Exfiltration & Extortion: $1.4M | Regulatory Fines: $420K | Client Notification: $280K",
        "technicalFinding": "Security group sg-0db948 allows SSH port 22 directly from 0.0.0.0/0 to the primary transactional Aurora Postgres database gateway bastion.",
        "businessImpact": "Catastrophic data breach of primary transactional financial ledger, regulatory fines, and irreparable enterprise reputation loss.",
        "solutionPlan": "Phase 1: Instantly revoke 0.0.0.0/0 inbound rules on security group sg-0db948. Phase 2: Route all administrative access through AWS Systems Manager (SSM) Session Manager without open ports. Phase 3: Enforce hardware MFA for bastion sessions."
    },
    {
        "id": "MCH-03",
        "name": "Container Runtime Privilege Escalation & Host Namespace Escape",
        "targetGroup": "Shared Worker Nodes",
        "source": "EDR",
        "threatActor": "Malicious Tenant / Internal Exploit Pipeline",
        "attackVector": "T1611 - Escape to Host",
        "cveList": "CVE-2024-21626 (runc Leaky Vessels), CWE-403",
        "complianceImpact": "SOC 2 Type II CC6.6, ISO 27001 Annex A.12",
        "annualProbability": "64% Annualized Likelihood",
        "baseLoss": 590000,
        "baseCost": 24000,
        "lossBreakdown": "Node Re-imaging & Forensics: $280K | Service Interruption: $190K | Compliance Review: $120K",
        "technicalFinding": "Worker node host runc binary version 1.1.11 contains known file descriptor leak vulnerability allowing containerized processes to access host root filesystem.",
        "businessImpact": "Compromised microservice escapes container sandbox to gain root access over underlying Linux host.",
        "solutionPlan": "Phase 1: Upgrade containerd and runc packages across all AMI node groups. Phase 2: Deploy Kyverno/Gatekeeper admission policies disallowing privileged container execution. Phase 3: Implement read-only root filesystems."
    },
    {
        "id": "MCH-04",
        "name": "Internal Microservice Mesh Missing Mutual TLS (mTLS) Encryption",
        "targetGroup": "Internal Microservices Mesh",
        "source": "SIEM + EDR",
        "threatActor": "Compromised Internal Pod / Lateral Eavesdropper",
        "attackVector": "T1040 - Network Sniffing",
        "cveList": "CWE-319 Cleartext Transmission of Sensitive Information",
        "complianceImpact": "PCI-DSS v4.0 Req 4.1, HIPAA Security Rule §164.312(e)",
        "annualProbability": "49% Annualized Likelihood",
        "baseLoss": 310000,
        "baseCost": 26000,
        "lossBreakdown": "Token Harvesting: $170K | Incident Investigation: $90K | Policy Penalties: $50K",
        "technicalFinding": "East-west traffic between checkout and payment tokenization services flows over plaintext HTTP without cryptographic authentication.",
        "businessImpact": "Internal network sniffing by compromised sidecar container can capture sensitive session tokens and payment payloads in transit.",
        "solutionPlan": "Phase 1: Enable STRICT mTLS mode across Istio/Linkerd service mesh. Phase 2: Deploy automated cert-manager certificate rotation with 24-hour validity periods."
    },
    {
        "id": "MCH-05",
        "name": "Legacy Staging Batch Server Unquoted Service Path Insecurity",
        "targetGroup": "Staging Windows Host",
        "source": "EDR",
        "threatActor": "Local Low-Privilege Account",
        "attackVector": "T1574.009 - Path Interception by Unquoted Path",
        "cveList": "CWE-428 Unquoted Search Path or Element",
        "complianceImpact": "Low Statutory Risk (Isolated QA Subnet)",
        "annualProbability": "7% Annualized Likelihood",
        "baseLoss": 7200,
        "baseCost": 31000,
        "lossBreakdown": "Local host re-imaging: $7,200",
        "technicalFinding": "Isolated QA batch runner Windows host has unquoted service path in C:\\Program Files\\Test Tools\\runner.exe. Host contains no production keys.",
        "businessImpact": "Theoretical local privilege escalation on a sandbox machine scheduled for retirement next quarter ($7,200 risk).",
        "solutionPlan": "Fixing involves contractor legacy service overhaul ($31,000). Spending $31K to mitigate $7.2K risk has -77% ROI. Accept risk until server decommission."
    },
    {
        "id": "MCH-06",
        "name": "Internal Test Database Bastion ICMP Echo (Ping) Response Enabled",
        "targetGroup": "Internal Test VPC Bastion",
        "source": "SIEM",
        "threatActor": "Internal Network Scanner",
        "attackVector": "T1046 - Network Service Discovery",
        "cveList": "N/A (RFC 792 ICMP Diagnostic Feature)",
        "complianceImpact": "None",
        "annualProbability": "4% Annualized Likelihood",
        "baseLoss": 2000,
        "baseCost": 18000,
        "lossBreakdown": "Internal audit overhead: $2,000",
        "technicalFinding": "Internal sandbox gateway responds to ICMP echo requests inside internal private VPC 10.14.0.0/16.",
        "businessImpact": "Negligible financial loss ($2,000). Reconfiguring firewall rules across legacy terraform modules costs $18,000 in dev hours.",
        "solutionPlan": "Accept risk. ICMP echo facilitates internal network troubleshooting without introducing external security exposure."
    },
    {
        "id": "MCH-07",
        "name": "Unpatched Kernel TCP SACK Panic Vulnerability in Cache Tier",
        "targetGroup": "Redis / Memcached Nodes",
        "source": "EDR + SIEM",
        "threatActor": "Remote Denial-of-Service Actor",
        "attackVector": "T1498 - Network Denial of Service",
        "cveList": "CVE-2019-11477 (TCP SACK Panic), CWE-400",
        "complianceImpact": "SOC 2 Type II CC7.1 (System Availability)",
        "annualProbability": "52% Annualized Likelihood",
        "baseLoss": 380000,
        "baseCost": 17000,
        "lossBreakdown": "Cache Outage Downtime: $240K | Cluster Recovery: $90K | SLA Credits: $50K",
        "technicalFinding": "6 Redis cache cluster instances run Linux kernel 4.14 susceptible to remote TCP SACK panic kernel crashes via malformed sequence packets.",
        "businessImpact": "Cascading cache invalidation causing direct load spikes on backend relational database leading to tier-1 service degradation.",
        "solutionPlan": "Phase 1: Disable TCP SACK via sysctl net.ipv4.tcp_sack=0 immediately. Phase 2: Execute rolling patch to Amazon Linux 2023 LTS kernel."
    }
]


def get_router():
    """Initializes and returns the singleton Laya Router instance."""
    global router_instance
    if router_instance is None:
        logger.info("Initializing Local Laya Router...")
        from laya import Router
        # Pin model checkpoints to ensure reliable local execution without unneeded network downloads
        router_instance = Router(
            models={
                "english": "convaiinnovations/laya",
                "multilingual": "convaiinnovations/laya",
                "typed-decisions": "convaiinnovations/laya"
            },
            default="english"
        )
        logger.info("Local Laya Router successfully initialized.")
    return router_instance


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown."""
    logger.info("Starting Local Laya AI Cyber Risk Quantification Service...")
    try:
        # Warm up the Laya model on startup
        get_router()
        logger.info("Laya model loaded and ready for local inference.")
    except Exception as e:
        logger.error(f"Failed to initialize Laya model during startup: {e}")
    yield
    logger.info("Shutting down Local Laya AI Service.")


app = FastAPI(
    title="Local Laya AI Cyber Risk Quantification Service",
    description="Local non-autoregressive decision engine for cyber risk analysis and actuarial quantification",
    version="0.4.1",
    lifespan=lifespan
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic Schemas
class FileDetail(BaseModel):
    name: str
    size: Optional[int] = 1024
    sourceType: Optional[str] = "Unknown"


class DetectedSources(BaseModel):
    siem: bool = False
    edr: bool = False
    iam: bool = False


class ClassifyRequest(BaseModel):
    state: str = Field(..., min_length=3, description="Telemetry finding, alert, or threat description")
    targetGroup: Optional[str] = None
    source: Optional[str] = None


class QuantifyRequest(BaseModel):
    filename: Optional[str] = "telemetry_bundle.zip"
    fileCount: Optional[int] = 0
    fileDetails: Optional[List[FileDetail]] = []
    detectedSources: Optional[DetectedSources] = None
    rawFindings: Optional[List[Dict[str, Any]]] = None


class VulnerabilityResult(BaseModel):
    id: str
    category: str
    name: str
    targetGroup: str
    source: str
    threatActor: str
    attackVector: str
    cveList: str
    complianceImpact: str
    annualProbability: str
    lossIfIgnored: float
    solutionCost: float
    lossBreakdown: str
    severity: str
    technicalFinding: str
    businessImpact: str
    solutionPlan: str
    recommendation: str
    aiEngine: str = "Local Laya AI (convaiinnovations/laya)"
    layaDecision: Optional[Dict[str, Any]] = None


@app.get("/health")
@app.get("/api/health")
async def health_check():
    """Health check endpoint providing engine status and device info."""
    is_ready = router_instance is not None
    return {
        "status": "healthy" if is_ready else "initializing",
        "engine": "Local Laya AI",
        "model": "convaiinnovations/laya",
        "architecture": "Non-Autoregressive Decision Engine (ModernBERT-large)",
        "device": "cpu",
        "ready": is_ready,
        "supportedQuestionTypes": ["choice", "score", "noul"]
    }


@app.post("/api/classify")
async def classify_threat(request: ClassifyRequest):
    """
    Classifies an individual cyber risk telemetry finding using local Laya inference.
    Evaluates threat domain, actuarial severity, and recommendation priority.
    """
    if not request.state or len(request.state.strip()) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State description must contain at least 3 characters."
        )

    router = get_router()
    try:
        t0 = time.time()
        prediction = router.predict(request.state, CYBER_RISK_QUESTIONS)
        elapsed_ms = round((time.time() - t0) * 1000, 2)

        answers = prediction.get("answers", {})
        domain_choice = answers.get("domain", {}).get("choice", "internal")
        severity_choice = answers.get("severity", {}).get("choice", "Medium")
        rec_choice = answers.get("recommendation", {}).get("choice", "Remediate in Sprint")
        active_exploit_prob = answers.get("active_exploit", {}).get("noul", 0.5)
        compliance_prob = answers.get("compliance_impact", {}).get("noul", 0.5)

        return {
            "state": request.state,
            "domain": domain_choice,
            "severity": severity_choice,
            "recommendation": rec_choice,
            "activeExploitLikelihood": active_exploit_prob,
            "complianceImpactLikelihood": compliance_prob,
            "inferenceTimeMs": elapsed_ms,
            "model": prediction.get("routing", {}).get("model", "english"),
            "rawAnswers": answers
        }
    except Exception as e:
        logger.error(f"Inference error in classify_threat: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Local Laya inference failed: {str(e)}"
        )


@app.post("/api/quantify", response_model=List[VulnerabilityResult])
async def quantify_telemetry(request: QuantifyRequest):
    """
    Performs full Cyber Risk Quantification across the submitted telemetry bundle.
    Uses Local Laya AI to classify all candidate findings while maintaining
    deterministic FAIR actuarial calculations.
    """
    router = get_router()
    results: List[VulnerabilityResult] = []

    # Incorporate dynamic raw findings from telemetry bundle logs if provided
    candidates = list(CANDIDATE_VULNERABILITY_TEMPLATES)
    if request.rawFindings and len(request.rawFindings) > 0:
        logger.info(f"Received {len(request.rawFindings)} dynamically extracted telemetry findings.")
        for idx, rf in enumerate(request.rawFindings):
            dyn_id = rf.get("id") or f"DYN-{str(idx + 1).zfill(2)}"
            candidates.insert(0, {
                "id": dyn_id,
                "name": rf.get("name", "Extracted Telemetry Anomaly"),
                "targetGroup": rf.get("targetGroup", "Enterprise Assets"),
                "source": rf.get("source", "Telemetry Logs"),
                "threatActor": rf.get("threatActor", "Opportunistic Threat Actor"),
                "attackVector": rf.get("attackVector", "T1190 - Exploit Public-Facing Application"),
                "cveList": rf.get("cveList", "CWE-699 Software Flaw"),
                "complianceImpact": rf.get("complianceImpact", "SOC 2 Type II, ISO 27001"),
                "annualProbability": rf.get("annualProbability", "70% Annualized Likelihood"),
                "baseLoss": float(rf.get("lossIfIgnored") or rf.get("baseLoss") or 450000),
                "baseCost": float(rf.get("solutionCost") or rf.get("baseCost") or 18000),
                "lossBreakdown": rf.get("lossBreakdown", "Direct Incident Response & Remediation"),
                "technicalFinding": rf.get("technicalFinding", "Anomaly identified in extracted log stream."),
                "businessImpact": rf.get("businessImpact", "Operational disruption and security posture compromise."),
                "solutionPlan": rf.get("solutionPlan", "Isolate affected node, rotate credentials, apply security patch.")
            })

    # Prepare requests for Laya inference
    laya_requests = []
    for candidate in candidates:
        state_text = f"{candidate['name']}. {candidate['technicalFinding']} Impact: {candidate['businessImpact']}"
        laya_requests.append({
            "state": state_text,
            "questions": CYBER_RISK_QUESTIONS
        })

    # Run local Laya inference
    t0 = time.time()
    try:
        # Run batch prediction through Laya Router
        predictions = router.predict_batch(laya_requests)
    except Exception as e:
        logger.warning(f"Laya predict_batch encountered an error ({e}), falling back to iterative predict.")
        predictions = []
        for req in laya_requests:
            try:
                p = router.predict(req["state"], req["questions"])
                predictions.append(p)
            except Exception as single_err:
                logger.error(f"Single inference error: {single_err}")
                predictions.append(None)

    total_time_ms = round((time.time() - t0) * 1000, 2)
    logger.info(f"Classified {len(candidates)} findings with Local Laya AI in {total_time_ms} ms.")

    for i, candidate in enumerate(candidates):
        pred = predictions[i] if i < len(predictions) else None
        answers = pred.get("answers", {}) if pred else {}

        # Extract Laya classifications
        laya_category = answers.get("domain", {}).get("choice")
        laya_severity = answers.get("severity", {}).get("choice")
        laya_rec = answers.get("recommendation", {}).get("choice")
        active_exploit_val = answers.get("active_exploit", {}).get("noul", 0.5)

        # Validate against allowed enum sets
        final_category = laya_category if laya_category in ["internal", "external", "machines"] else candidate["id"][:3].lower()
        if final_category not in ["internal", "external", "machines"]:
            final_category = "internal" if "INT" in candidate["id"] else ("external" if "EXT" in candidate["id"] else "machines")

        # Severity classification: validated Laya output
        final_severity = laya_severity if laya_severity in ["Severe", "Medium", "Ignorable"] else "Medium"

        # Deterministic loss and cost calculation based on validated FAIR actuarial ranges
        # Keep numerical calculations strictly deterministic and separate from AI confidence
        base_loss = candidate["baseLoss"]
        base_cost = candidate["baseCost"]

        # Actuarial calibration: adjust dollar loss deterministically according to validated severity
        if final_severity == "Severe":
            loss_value = max(base_loss, 500000)
            cost_value = min(base_cost, 45000)
            rec_text = "Immediate Remediation (ROI: +3,000%+)"
        elif final_severity == "Medium":
            loss_value = min(max(base_loss, 50000), 550000)
            cost_value = base_cost
            rec_text = "Remediate in Sprint (Positive ROI)"
        else:  # Ignorable
            loss_value = min(base_loss, 25000)
            cost_value = max(base_cost, 20000)
            rec_text = "Deprioritize / Accept Risk (Negative ROI)"

        results.append(VulnerabilityResult(
            id=candidate["id"],
            category=final_category,
            name=candidate["name"],
            targetGroup=candidate["targetGroup"],
            source=candidate["source"],
            threatActor=candidate["threatActor"],
            attackVector=candidate["attackVector"],
            cveList=candidate["cveList"],
            complianceImpact=candidate["complianceImpact"],
            annualProbability=candidate["annualProbability"],
            lossIfIgnored=float(loss_value),
            solutionCost=float(cost_value),
            lossBreakdown=candidate["lossBreakdown"],
            severity=final_severity,
            technicalFinding=candidate["technicalFinding"],
            businessImpact=candidate["businessImpact"],
            solutionPlan=candidate["solutionPlan"],
            recommendation=rec_text,
            aiEngine="Local Laya AI (convaiinnovations/laya)",
            layaDecision={
                "predictedDomain": laya_category,
                "predictedSeverity": laya_severity,
                "domainConfidence": answers.get("domain", {}).get("answer_confidence"),
                "severityConfidence": answers.get("severity", {}).get("answer_confidence"),
                "activeExploitLikelihood": active_exploit_val
            }
        ))

    return results


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "127.0.0.1")
    logger.info(f"Starting server on {host}:{port}...")
    uvicorn.run("backend.service:app", host=host, port=port, reload=False)
