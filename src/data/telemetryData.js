// Realistic Cyber Risk Quantification Telemetry Data
// Categorized into Internal (Employees & Devs), External (Customers & Vendors), and Machines (Servers & Cloud Infra)

export const DEFAULT_VULNERABILITIES = [
  // ===================== INTERNAL PEOPLE (Employees & Devs) =====================
  {
    id: "INT-01",
    category: "internal",
    name: "Hardcoded Production AWS Credentials in Dev Git Repos",
    targetGroup: "Developers / DevOps",
    source: "IAM + SIEM",
    threatActor: "Nation-State APT & Automated Secret Scrapers",
    attackVector: "T1552.001 - Unsecured Credentials in Code Repositories",
    cveList: "CWE-798 Hardcoded Credentials, CWE-522",
    complianceImpact: "SOC 2 Type II CC6.1, SEC 4-Day Incident Rule, ISO 27001 A.9.4",
    annualProbability: "82% Annualized Likelihood",
    lossIfIgnored: 1250000,
    solutionCost: 18000,
    lossBreakdown: "Ransomware Extortion: $650K | Forensic Audit: $280K | Cloud Resource Theft: $320K",
    severity: "Severe",
    technicalFinding: "4 engineers committed unmasked AWS_SECRET_ACCESS_KEY credentials to active feature branch repositories with root permissions.",
    businessImpact: "Direct infrastructure takeover, crypto-mining hijacking, or proprietary code exfiltration causing $1.25M in downtime and liability.",
    solutionPlan: "Phase 1: Invalidate leaked keys immediately and revoke active STS sessions. Phase 2: Deploy TruffleHog pre-commit git hooks. Phase 3: Enforce AWS IAM Identity Center temporary role assumption.",
    recommendation: "Immediate Remediation (ROI: +6,844%)"
  },
  {
    id: "INT-02",
    category: "internal",
    name: "Finance Team Phishing Vulnerability / Weak MFA Token",
    targetGroup: "Finance & Payroll Employees",
    source: "IAM + EDR",
    threatActor: "FIN7 / Business Email Compromise (BEC) Cartels",
    attackVector: "T1566.002 - Spearphishing Link & T1621 MFA Fatigue",
    cveList: "CWE-308 Use of Implicit Intent for Authentication",
    complianceImpact: "SOX 404 Internal Controls, GLBA Safeguards Rule, PCI-DSS v4.0",
    annualProbability: "74% Annualized Likelihood",
    lossIfIgnored: 820000,
    solutionCost: 12000,
    lossBreakdown: "Direct Wire Fraud: $520K | Forensic Legal Fees: $180K | Cyber Insurance Deductible: $120K",
    severity: "Severe",
    technicalFinding: "18 finance personnel using SMS-based 2FA; SIEM logs show 3 credential brute-force anomalies from foreign IP subnets bypassing geolocation controls.",
    businessImpact: "Wire fraud, payroll diversion, and executive impersonation with average recovery cost exceeding $820K.",
    solutionPlan: "Phase 1: Disable legacy SMS MFA fallbacks across Okta/Entra. Phase 2: Issue YubiKey FIDO2 hardware keys to all payroll approvers. Phase 3: Implement dual-authorization verification for wire transfers over $25K.",
    recommendation: "Immediate Remediation (ROI: +6,733%)"
  },
  {
    id: "INT-03",
    category: "internal",
    name: "Unsanctioned Generative AI Tool Usage with Proprietary Data",
    targetGroup: "Product & Marketing Staff",
    source: "EDR + SIEM",
    threatActor: "Untrusted AI Vendors & Third-Party Training Harvesters",
    attackVector: "T1567 - Exfiltration Over Web Service (Shadow AI)",
    cveList: "OWASP Top 10 for LLM: LLM06 Sensitive Information Disclosure",
    complianceImpact: "GDPR Article 32, EU AI Act, Customer NDA Agreements",
    annualProbability: "68% Annualized Likelihood",
    lossIfIgnored: 340000,
    solutionCost: 25000,
    lossBreakdown: "IP Invalidation & Litigation: $220K | Regulatory Fines: $80K | Customer Notifications: $40K",
    severity: "Medium",
    technicalFinding: "EDR web-filtering logged 2,400+ clipboard pastes containing roadmap drafts and internal schema into unauthorized consumer AI tools.",
    businessImpact: "Trade secret leakage, potential IP invalidation, and contractual non-disclosure breach risks.",
    solutionPlan: "Phase 1: Block consumer AI endpoints via Cloudflare CASB/SWG. Phase 2: Provision enterprise-tier ChatGPT/Claude licenses with zero-retention data isolation. Phase 3: Deliver mandatory IP security micro-training.",
    recommendation: "Remediate in Sprint (ROI: +1,260%)"
  },
  {
    id: "INT-04",
    category: "internal",
    name: "Developer Local Root Access & Disabled Full-Disk Encryption",
    targetGroup: "Engineering Staff",
    source: "EDR",
    threatActor: "Physical Device Thieves & Opportunistic Actors",
    attackVector: "T1200 - Hardware Additions / Physical Access",
    cveList: "CWE-311 Missing Encryption of Sensitive Data",
    complianceImpact: "SOC 2 Type II CC6.6, HIPAA Security Rule §164.312",
    annualProbability: "35% Annualized Likelihood",
    lossIfIgnored: 190000,
    solutionCost: 14000,
    lossBreakdown: "Physical Asset Loss: $20K | Data Breach Audit: $110K | Token Invalidation: $60K",
    severity: "Medium",
    technicalFinding: "12 MacBook Pros identified with FileVault disabled and non-enforced screen timeout locks in remote worker locations.",
    businessImpact: "Hardware theft leading to raw source code and local cookie token compromise ($190K forensic audit).",
    solutionPlan: "Phase 1: Push non-bypassable FileVault2 configuration profiles via Jamf Pro. Phase 2: Enforce 5-minute inactivity locks with biometric TouchID. Phase 3: Enable automated remote wipe on 3 failed attempts.",
    recommendation: "Remediate in Sprint (ROI: +1,257%)"
  },
  {
    id: "INT-05",
    category: "internal",
    name: "Internal Staging Wiki Default Admin Password (Isolated Subnet)",
    targetGroup: "Internal Wiki Users",
    source: "IAM",
    threatActor: "Internal Curious Staff / Non-Malicious Insider",
    attackVector: "T1078.001 - Default Accounts on Isolated Host",
    cveList: "CWE-255 Default Credentials",
    complianceImpact: "Low Regulatory Exposure (No Customer Data, Internal Only)",
    annualProbability: "8% Annualized Likelihood",
    lossIfIgnored: 6000,
    solutionCost: 38000,
    lossBreakdown: "Maximum cleanup cost: $6,000 internal IT hours",
    severity: "Ignorable",
    technicalFinding: "Archived internal documentation server on 10.0.9.x running mediawiki with generic admin credentials behind 2 layers of corporate VPN.",
    businessImpact: "Low. Data is 4-year-old internal lunch menu and stale onboarding markdown. Actual loss cap is ~$6K.",
    solutionPlan: "Requires migrating legacy MySQL 5.5 and re-architecting deprecated Wiki extensions ($38K contractor quote). Advise accepting risk.",
    recommendation: "Deprioritize / Accept Risk (Loss: $6K vs Fix: $38K -> Negative ROI)"
  },
  {
    id: "INT-06",
    category: "internal",
    name: "Developer Staging SSH Key Sharing across Sandbox Environments",
    targetGroup: "Junior Devs",
    source: "IAM",
    threatActor: "Non-Privileged Sandbox Experimenters",
    attackVector: "T1078.003 - Local Accounts on Ephemeral Containers",
    cveList: "CWE-521 Weak Password / Key Sharing",
    complianceImpact: "Isolated Non-Prod Scope (Excluded from SOC 2 Boundary)",
    annualProbability: "12% Annualized Likelihood",
    lossIfIgnored: 8500,
    solutionCost: 29000,
    lossBreakdown: "Ephemeral container teardown and re-provision: $8,500",
    severity: "Ignorable",
    technicalFinding: "Shared SSH key pair used on non-routable ephemeral developer sandbox boxes that reset nightly.",
    businessImpact: "Ephemeral containers destroyed every 24 hours. No production connectivity or persistent data stored.",
    solutionPlan: "Full PKI infrastructure overhaul for ephemeral test containers requiring 120 dev hours. Advise accepting risk.",
    recommendation: "Deprioritize / Accept Risk (Loss: $8.5K vs Fix: $29K -> Negative ROI)"
  },

  // ===================== EXTERNAL ENTITIES (Customers & Vendors) =====================
  {
    id: "EXT-01",
    category: "external",
    name: "Customer Auth API Endpoint Lacking Adaptive Rate Limiting",
    targetGroup: "Customer Authentication",
    source: "SIEM",
    threatActor: "Organized Credential Stuffing Syndicates",
    attackVector: "T1110.003 - Credential Stuffing & T1190 Exploit Public App",
    cveList: "CWE-307 Improper Restriction of Excessive Authentication Attempts",
    complianceImpact: "SEC Material Cyber Disclosure, FTC Act Section 5, GDPR Art 33",
    annualProbability: "91% Annualized Likelihood",
    lossIfIgnored: 1450000,
    solutionCost: 32000,
    lossBreakdown: "Account Takeover Reimbursements: $750K | Regulatory Fines: $400K | Incident PR: $300K",
    severity: "Severe",
    technicalFinding: "Customer login gateway /v2/auth/token accepts unlimited attempts; SIEM flagged 420K credential stuffing events this month without IP bans.",
    businessImpact: "Account takeovers (ATO), customer balance theft, brand reputation damage, and class-action notification costs.",
    solutionPlan: "Phase 1: Enforce IP rate limiting on Cloudflare WAF (max 5 requests/minute). Phase 2: Deploy Cloudflare Bot Management with risk-based challenge. Phase 3: Implement breach-password detection check on password submit.",
    recommendation: "Immediate Remediation (ROI: +4,431%)"
  },
  {
    id: "EXT-02",
    category: "external",
    name: "Customer Data Leak Exposure via S3 Bucket ACL Drift",
    targetGroup: "Customer Data Storage",
    source: "IAM + SIEM",
    threatActor: "Autonomous Cloud Asset Harvesters & Competitors",
    attackVector: "T1530 - Data from Cloud Storage Object",
    cveList: "CWE-732 Incorrect Permission Assignment for Critical Resource",
    complianceImpact: "GDPR Article 32 & 33 (4% global turnover risk), CCPA / CPRA statutory penalties",
    annualProbability: "79% Annualized Likelihood",
    lossIfIgnored: 980000,
    solutionCost: 15000,
    lossBreakdown: "Regulatory GDPR Fines: $520K | Mandatory Forensic Notices: $260K | Churn: $200K",
    severity: "Severe",
    technicalFinding: "An enterprise report storage bucket was modified to allow public READ via a misconfigured Terraform lifecycle rule drift.",
    businessImpact: "GDPR / CCPA violation fines up to $980K, mandatory 72-hour regulatory disclosure, and customer churn.",
    solutionPlan: "Phase 1: Enable AWS S3 Block Public Access at the AWS Organization root. Phase 2: Deploy AWS Config auto-remediation rule. Phase 3: Implement Terraform drift detection in GitHub Actions CI.",
    recommendation: "Immediate Remediation (ROI: +6,433%)"
  },
  {
    id: "EXT-03",
    category: "external",
    name: "Third-Party Billing Vendor API Webhook Missing HMAC Validation",
    targetGroup: "SaaS Billing Vendor",
    source: "SIEM",
    threatActor: "Financially-Motivated Fraud Syndicates",
    attackVector: "T1565.001 - Data Manipulation / Webhook Forgery",
    cveList: "CWE-345 Insufficient Verification of Data Authenticity",
    complianceImpact: "PCI-DSS v4.0 Requirement 6.4, AICPA SOC 2 Processing Integrity",
    annualProbability: "62% Annualized Likelihood",
    lossIfIgnored: 420000,
    solutionCost: 22000,
    lossBreakdown: "Fraudulent Order Losses: $280K | Accounting Reconciliation: $85K | Legal Review: $55K",
    severity: "Medium",
    technicalFinding: "Inbound webhook endpoint parses JSON payment confirmation payloads without cryptographically verifying the vendor HMAC-SHA256 signature.",
    businessImpact: "Fake payment injection causing fraudulent order fulfillments and invoice ledger discrepancies ($420K).",
    solutionPlan: "Phase 1: Reject unverified webhook payloads missing X-Signature header. Phase 2: Implement SHA256 HMAC cryptographic verification with 300s timestamp replay window. Phase 3: Restrict inbound webhooks to vendor IP CIDRs.",
    recommendation: "Remediate in Sprint (ROI: +1,809%)"
  },
  {
    id: "EXT-04",
    category: "external",
    name: "Dormant Contractor Vendor Accounts (Inactive > 60 Days)",
    targetGroup: "External Vendors",
    source: "IAM",
    threatActor: "Supply-Chain Attackers & Opportunistic Actors",
    attackVector: "T1078.002 - Domain Accounts / Dormant Vendor Accounts",
    cveList: "CWE-262 Not Using Password Aging / Session Limits",
    complianceImpact: "SOC 2 CC6.2 User Access Deprovisioning, ISO 27001 A.9.2.6",
    annualProbability: "53% Annualized Likelihood",
    lossIfIgnored: 275000,
    solutionCost: 11000,
    lossBreakdown: "Unauthorized Lateral Access & Incident Response: $275,000",
    severity: "Medium",
    technicalFinding: "14 external vendor contractor accounts remain enabled with active SAML tokens despite project wrap-up 2+ months ago.",
    businessImpact: "Compromised vendor credentials used as initial access vector to bypass external perimeter.",
    solutionPlan: "Phase 1: Immediately disable contractor accounts inactive >30 days. Phase 2: Integrate vendor SCIM deprovisioning with vendor procurement system. Phase 3: Mandate monthly IAM vendor access audits.",
    recommendation: "Remediate in Sprint (ROI: +2,400%)"
  },
  {
    id: "EXT-05",
    category: "external",
    name: "External Vendor Marketing Pixel Cookie Banner Non-Compliance",
    targetGroup: "Marketing Vendors",
    source: "SIEM",
    threatActor: "Automated Privacy Scraping Bots",
    attackVector: "T1596 - Search Open Technical Databases",
    cveList: "CWE-359 Privacy Violation",
    complianceImpact: "Minor Privacy Injunction (Low Enforcement Probability)",
    annualProbability: "5% Annualized Likelihood",
    lossIfIgnored: 12000,
    solutionCost: 45000,
    lossBreakdown: "Statutory cure response costs: $12,000",
    severity: "Ignorable",
    technicalFinding: "An obsolete vendor tracking pixel loads on an unindexed Spanish legacy blog page before user consent.",
    businessImpact: "Page receives ~14 visits per month. Low regulatory interest, statutory remedy notice period permits 30-day cure.",
    solutionPlan: "Requires agency contract renegotiation, legal compliance review, and rebuilding legacy CMS template ($45K estimate). Advise accepting risk.",
    recommendation: "Deprioritize / Accept Risk (Loss: $12K vs Fix: $45K -> Negative ROI)"
  },
  {
    id: "EXT-06",
    category: "external",
    name: "Public Status Page Subdomain Missing DNSSEC Signature",
    targetGroup: "External Status Page",
    source: "SIEM",
    threatActor: "DNS Hijackers (Theoretically)",
    attackVector: "T1584.004 - DNS Compromise",
    cveList: "CWE-346 Origin Validation Error",
    complianceImpact: "None (Static External Status Host)",
    annualProbability: "2% Annualized Likelihood",
    lossIfIgnored: 4500,
    solutionCost: 31000,
    lossBreakdown: "DNS record propagation fix: $4,500",
    severity: "Ignorable",
    technicalFinding: "Status subdomain (status.company.com) points to external third-party status provider lacking DNSSEC validation.",
    businessImpact: "Low probability DNS cache poisoning on a static status page with zero credential capture mechanisms.",
    solutionPlan: "Migrating enterprise DNS provider zones across 14 registries with custom nameserver delegation. Advise accepting risk.",
    recommendation: "Deprioritize / Accept Risk (Loss: $4.5K vs Fix: $31K -> Negative ROI)"
  },

  // ===================== MACHINES (Servers & Cloud Infrastructure) =====================
  {
    id: "MCH-01",
    category: "machines",
    name: "Kubernetes Ingress Controller Remote Code Execution (CVE-2024-7646)",
    targetGroup: "Production K8s Cluster",
    source: "EDR + SIEM",
    threatActor: "Nation-State Threat Groups & Ransomware Operatives",
    attackVector: "T1190 - Exploit Public-Facing Application (RCE)",
    cveList: "CVE-2024-7646, CWE-120 Buffer Copy without Checking Size",
    complianceImpact: "SEC Material Cybersecurity Event, SOC 2 CC7.1, FedRAMP High",
    annualProbability: "88% Annualized Likelihood",
    lossIfIgnored: 2150000,
    solutionCost: 35000,
    lossBreakdown: "Cluster Rebuild: $450K | Business Interruption: $1.2M | Incident Counsel: $500K",
    severity: "Severe",
    technicalFinding: "Production ingress nginx pods vulnerable to memory corruption leading to ingress pod takeover and namespace escape across 2 AWS regions.",
    businessImpact: "Full production microservices breach, data destruction, and multi-day service blackout ($2.15M business loss).",
    solutionPlan: "Phase 1: Apply Helm chart patch to v1.11.2+ on staging and prod clusters. Phase 2: Enforce Pod Security Standards (Restricted) to prevent container escape. Phase 3: Deploy Cilium eBPF network policies blocking unauthorized pod egress.",
    recommendation: "Immediate Remediation (ROI: +6,042%)"
  },
  {
    id: "MCH-02",
    category: "machines",
    name: "Unrestricted Database Port 5432 Exposed on Bastion Gateway",
    targetGroup: "Database Servers",
    source: "EDR + IAM",
    threatActor: "Automated Ransomware Port Sweepers & Shodan Scrapers",
    attackVector: "T1046 - Network Service Discovery & T1110 Brute Force",
    cveList: "CWE-284 Improper Access Control",
    complianceImpact: "PCI-DSS v4.0 Requirement 1.3, HIPAA Security Rule §164.312",
    annualProbability: "84% Annualized Likelihood",
    lossIfIgnored: 1650000,
    solutionCost: 19000,
    lossBreakdown: "Ransom Demands & Restoration: $950K | Notification: $380K | Business Loss: $320K",
    severity: "Severe",
    technicalFinding: "Security group sg-091a1829 allowed ingress TCP 5432 from 0.0.0.0/0 to the primary transactional Aurora Postgres cluster.",
    businessImpact: "Automated ransomware bot scanning, credential dictionary attack, and unauthorized database dump ($1.65M exposure).",
    solutionPlan: "Phase 1: Immediately restrict security group sg-091a1829 ingress to 127.0.0.1. Phase 2: Deploy AWS Systems Manager (SSM) Session Manager for port forwarding without public IP. Phase 3: Enforce AWS Network Firewall inspection.",
    recommendation: "Immediate Remediation (ROI: +8,584%)"
  },
  {
    id: "MCH-03",
    category: "machines",
    name: "Outdated OpenSSL 3.0.2 on Core Payment Worker Nodes",
    targetGroup: "Payment Worker Nodes",
    source: "EDR",
    threatActor: "Opportunistic Remote Attackers",
    attackVector: "T1203 - Exploitation for Client Execution",
    cveList: "CVE-2022-3602, CVE-2022-3786, CWE-120",
    complianceImpact: "PCI-DSS v4.0 Req 6.3.3 Patching Mandate",
    annualProbability: "58% Annualized Likelihood",
    lossIfIgnored: 520000,
    solutionCost: 28000,
    lossBreakdown: "PCI Non-Compliance Fines: $300K | Emergency Engineering: $140K | Downtime: $80K",
    severity: "Medium",
    technicalFinding: "38 Ubuntu 22.04 worker nodes running vulnerable OpenSSL vulnerable to buffer overflow in X.509 certificate parsing.",
    businessImpact: "Worker node crash, denial of service during peak settlement hours, and PCI-DSS compliance failure ($520K).",
    solutionPlan: "Phase 1: Roll out blue-green AMI deployment with OpenSSL 3.0.13. Phase 2: Validate TLS handshakes in staging sandbox. Phase 3: Automate daily EC2 vulnerability scanning via AWS Inspector.",
    recommendation: "Remediate in Sprint (ROI: +1,757%)"
  },
  {
    id: "MCH-04",
    category: "machines",
    name: "Redis Cache Cluster Without AUTH Enabled in Internal VPC",
    targetGroup: "Cache Infrastructure",
    source: "SIEM",
    threatActor: "Malicious Internal Compromised Workstation / Lateral Mov.",
    attackVector: "T1021 - Remote Services & T1539 Steal Web Session Cookie",
    cveList: "CWE-306 Missing Authentication for Critical Function",
    complianceImpact: "SOC 2 CC6.3 Network Segmentation & Encryption in Transit",
    annualProbability: "48% Annualized Likelihood",
    lossIfIgnored: 380000,
    solutionCost: 24000,
    lossBreakdown: "Session Hijacking Losses: $220K | Token Revocation: $110K | IR: $50K",
    severity: "Medium",
    technicalFinding: "Redis 7.0 cache nodes accepting unauthenticated connections within private VPC subnet without password or TLS enforcement.",
    businessImpact: "Lateral movement target: an attacker with local pod access could poison cached session tokens ($380K risk).",
    solutionPlan: "Phase 1: Enable Redis AUTH password via AWS ElastiCache parameter group. Phase 2: Store rotating password in AWS Secrets Manager. Phase 3: Mandate in-transit TLS encryption for all Redis traffic.",
    recommendation: "Remediate in Sprint (ROI: +1,483%)"
  },
  {
    id: "MCH-05",
    category: "machines",
    name: "Legacy Print Server SMBv1 Protocol on Air-Gapped Test Lab",
    targetGroup: "Air-Gapped Test Lab",
    source: "EDR",
    threatActor: "WannaCry / EternalBlue Worms (Physical Interconnect Only)",
    attackVector: "T1210 - Exploitation of Remote Services (Legacy SMBv1)",
    cveList: "CVE-2017-0144 (EternalBlue), CWE-119",
    complianceImpact: "None (Air-Gapped Isolated Hardware Rig)",
    annualProbability: "2% Annualized Likelihood",
    lossIfIgnored: 8000,
    solutionCost: 42000,
    lossBreakdown: "Hardware re-imaging: $8,000",
    severity: "Ignorable",
    technicalFinding: "A standalone Windows Server 2008 physical machine running SMBv1 for a hardware calibration device with no internet egress.",
    businessImpact: "Machine is completely air-gapped on VLAN 999. Threat actor would need physical building breach + physical patch cable.",
    solutionPlan: "Replacing custom hardware calibration apparatus costs $42K in specialized industrial electronics. Advise accepting risk.",
    recommendation: "Deprioritize / Accept Risk (Loss: $8K vs Fix: $42K -> Negative ROI)"
  },
  {
    id: "MCH-06",
    category: "machines",
    name: "Deprecated NTP Daemon Minor Drift on Archival Cold Storage",
    targetGroup: "Cold Storage Nodes",
    source: "SIEM",
    threatActor: "Clock Drift Exploitation / Theoretical Man-in-the-Middle",
    attackVector: "T1583 - Acquire Infrastructure",
    cveList: "CWE-388 Error Handling Flaw",
    complianceImpact: "None (Archival Immutable WORM Media)",
    annualProbability: "1% Annualized Likelihood",
    lossIfIgnored: 3500,
    solutionCost: 26000,
    lossBreakdown: "Manual clock sync reboot: $3,500",
    severity: "Ignorable",
    technicalFinding: "Ntpd version 4.2.8p10 on immutable write-once optical cold storage system has minor clock jitter vulnerability.",
    businessImpact: "No cryptographic or transaction validation reliance. Negligible threat vector (<$3,500 maximum disruption).",
    solutionPlan: "Requires taking archival storage offline for vendor firmware recertification ($26K vendor fee). Advise accepting risk.",
    recommendation: "Deprioritize / Accept Risk (Loss: $3.5K vs Fix: $26K -> Negative ROI)"
  }
];

export function computeQuantificationSummary(vulnerabilities) {
  let totalLoss = 0;
  let totalCost = 0;
  let severeCount = 0;
  let mediumCount = 0;
  let ignorableCount = 0;

  vulnerabilities.forEach(item => {
    totalLoss += item.lossIfIgnored;
    // Only include solution costs for items worth fixing (Severe and Medium),
    // or include full solution cost to show the clear delta
    if (item.severity === "Severe") {
      severeCount++;
      totalCost += item.solutionCost;
    } else if (item.severity === "Medium") {
      mediumCount++;
      totalCost += item.solutionCost;
    } else if (item.severity === "Ignorable") {
      ignorableCount++;
      // Ignorable items: we advise NOT spending the fix cost
    }
  });

  // Net benefit = Total potential loss prevented by fixing severe & medium items minus solution cost
  const actionableLossPrevented = vulnerabilities
    .filter(v => v.severity !== "Ignorable")
    .reduce((sum, v) => sum + v.lossIfIgnored, 0);

  const netSavings = actionableLossPrevented - totalCost;

  return {
    totalLoss,
    totalCost,
    netSavings,
    totalCount: vulnerabilities.length,
    severeCount,
    mediumCount,
    ignorableCount
  };
}

export function formatCurrency(amount) {
  if (Math.abs(amount) >= 1000000) {
    return `$${(amount / 1000000).toFixed(2)}M`;
  }
  if (Math.abs(amount) >= 1000) {
    return `$${(amount / 1000).toFixed(0)}K`;
  }
  return `$${amount.toLocaleString()}`;
}

export function formatExactCurrency(amount) {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(amount);
}
