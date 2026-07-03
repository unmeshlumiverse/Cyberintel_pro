// ═══════════════════════════════════════════════════════════════════════
// LUMIVERSE SOLUTIONS — COMPLETE KNOWLEDGE BASE
// Sources: Cyber Ambassador PDF | RBI UCB Excel (59+35+25+30 controls)
//          Battle Card Excel (27 security products) | Pricing Excel
// ═══════════════════════════════════════════════════════════════════════

const KNOWLEDGE_BASE = {

  // ── LUMIVERSE CREDENTIALS ─────────────────────────────────────────────
  credentials: [
    'CERT-In empanelled — MANDATORY for RBI/SEBI/IRDAI compliance audits',
    '350+ Bank VAPT Audits — including UCBs, SCBs, NBFCs',
    '135+ UCB Banks Consulted and Audited across Maharashtra and India',
    '650+ Digital Forensics cases solved with Maharashtra Police (2016–2024)',
    '1500+ Cyber Awareness Campaigns across Indian universities and colleges',
    '750+ Cyber Awareness Sessions for banks — Cyber Ambassador program',
    'Working with Maharashtra Police — Nashik, Kolhapur, Mumbai regions',
    'UdyogWardhini Star Udyojak Award recipient',
    'Consulting Nashik Police for 250+ cybercrime cases',
    'Guest lecturer — Detective Training School (DTS), HAL Ozar Nashik, Airforce Borgad, Deolali Military',
    'Cyber Security Faculty — MSME, Kolhapur University, SNJB COE Nashik',
    'CEH, CISA, ECSA, LPT, CHFI, CISSP, CISM, OSCP certified team',
    'Director Amar Thakare — advisor on cyber cases, IR teams, forensics cases',
    'India + Dubai presence — covers cross-border regulatory compliance',
    'Mentoring Indian defense security products',
    'Lumiverse × Cyber Ambassador — specialized UCB banking security partnership'
  ],

  // ── UCB FRAMEWORK — COMPLETE CONTROLS BY LEVEL ───────────────────────
  // Source: RBI_UCB_All4Levels_Separate.xlsx — 147 total controls
  ucb_levels: {
    Level_I: {
      total_controls: 59,
      applicable_to: 'ALL UCBs — CBS-only banks with internet banking OR mobile banking OR CTS/IMPS/UPI membership',
      critical_controls: [
        '[L1-GOV-01] Board approved Cyber Security Policy — distinct from IT/IS policy, annual review mandatory',
        '[L1-GOV-02] Policy communicated to RBI DCBS Regional Office annually',
        '[L1-GOV-05] Cyber Crisis Management Plan (CCMP) — documented and tested',
        '[L1-EML-01] Bank-specific email domain + DMARC policy set to reject/quarantine + SPF + DKIM',
        '[L1-ACC-01] Two-Factor Authentication (2FA) for ALL CBS application access',
        '[L1-VAPT-01] Network Infrastructure VAPT — CERT-In empanelled vendor — annually',
        '[L1-INC-01] Incident Response Plan — documented, tested, with RBI DCBS reporting',
        '[L1-POL-01] Policy implementation for all critical processes — ISP, AUP, PW policy, etc.',
        '[L1-AWR-01] Cyber security awareness for ALL staff levels — annual mandatory',
        '[L1-AST-01] Hardware and Software Asset Inventory — updated, classified by criticality',
        '[L1-ACC-02] User access control — RBAC, quarterly access review, least privilege',
        '[L1-ACC-03] Strong password policy — min 8 chars, complexity, 90-day rotation',
        '[L1-NW-01] Perimeter firewall — inbound and outbound traffic control',
        '[L1-LOG-01] Audit log capture — all critical system events — 180 days retention'
      ],
      lumiverse_services: 'Network VAPT + Email Security (DMARC/SPF/DKIM) + IS Audit + Cyber Awareness + Policy Framework + IRP + Asset Management',
      gap_indicators: ['No DMARC record', 'No SPF record', 'Generic email domain (@gmail/@yahoo)', 'No VAPT history visible', 'No Cyber Policy published', 'No CISO mentioned']
    },
    Level_II: {
      total_controls: 35,
      cumulative: 94,
      applicable_to: 'UCBs with internet banking OR mobile banking OR card payments OR RTGS/NEFT/IMPS',
      critical_controls: [
        '[L2-CSO-01] CISO appointment — dedicated role, NOT combined with Head of IT',
        '[L2-CSO-02] CISO reports directly to Board/MD/CEO — independent of IT function',
        '[L2-VAPT-01] Application VAPT — web banking portal, mobile app — CERT-In empanelled vendor',
        '[L2-VAPT-02] VA every 6 months; PT annually and after every major change',
        '[L2-IB-01] Internet banking — multi-factor authentication + session management + OTP controls',
        '[L2-IB-02] Fraud risk management for internet banking — real-time monitoring',
        '[L2-MB-01] Mobile banking app security — certificate pinning, root detection, secure storage',
        '[L2-MB-02] Mobile banking VAPT — CERT-In empanelled vendor annually',
        '[L2-DLP-01] Data Loss Prevention — email, web, endpoint channels',
        '[L2-FW-01] Multi-layer firewall — stateful inspection, application-aware filtering',
        '[L2-DMZ-01] DMZ implementation for internet-facing services',
        '[L2-IDS-01] Network-based IDS/IPS with real-time alerting',
        '[L2-NW-01] Network segmentation — CBS, Internet, ATM, HO, Branch networks SEPARATE',
        '[L2-LOG-01] Centralized log management — SIEM integration for anomaly detection'
      ],
      lumiverse_services: 'Web App VAPT + Mobile App VAPT + CISO appointment + DLP Implementation + Firewall Audit + SIEM + Network Segmentation Assessment',
      gap_indicators: ['No CISO on website', 'Internet banking without MFA evidence', 'No mobile app security visible', 'No SOC/SIEM', 'Single network for all operations']
    },
    Level_III: {
      total_controls: 25,
      cumulative: 119,
      applicable_to: 'UCBs with own ATM Switch OR SWIFT interface OR hosting DC for other banks',
      critical_controls: [
        '[L3-ATM-01] ATM dedicated VLAN — isolated from CBS and internet networks',
        '[L3-ATM-02] ATM switch access controls — dual authorization, privileged access management',
        '[L3-ATM-03] Physical security for ATM switch DC — biometric, CCTV',
        '[L3-SWF-01] SWIFT security — SWIFT Customer Security Programme (CSP) compliance',
        '[L3-SWF-02] SWIFT interface access — authenticated, limited, audited access',
        '[L3-SWF-03] SWIFT transaction monitoring — real-time anomaly detection',
        '[L3-DC-01] Data Centre security — geographically separated DC/DR',
        '[L3-DC-02] Physical access controls — biometric, mantraps, CCTV, visitor management',
        '[L3-ADV-01] Advanced Threat Defense — URL/IP/application whitelist management',
        '[L3-ADV-02] Endpoint protection with whitelist/blacklist enforcement',
        '[L3-ADV-03] Disable PowerShell and inter-process communication for non-critical systems',
        '[L3-ADV-04] Remote access for critical infrastructure — disabled or strictly controlled',
        '[L3-SEG-01] Segregation of duties — IT operations vs security vs audit roles'
      ],
      lumiverse_services: 'ATM Security Assessment + SWIFT VAPT + DC Physical Security Audit + Advanced Endpoint Protection + Network VAPT + PAM Implementation',
      gap_indicators: ['ATM Switch without dedicated VLAN', 'SWIFT without CSP audit', 'Shared admin credentials', 'No PAM visible', 'DC in same location as HO']
    },
    Level_IV: {
      total_controls: 30,
      cumulative: 147,
      applicable_to: 'Large/Scheduled UCBs with high digital depth, multiple payment integrations, C-SOC requirement',
      critical_controls: [
        '[L4-SOC-01] C-SOC with 24x7 monitoring — Level 1/2/3 analysts — dedicated staffing',
        '[L4-SOC-02] SOC use-case library — MITRE ATT&CK mapped for UCB-specific threats',
        '[L4-SOC-03] SOC SLA — P1: 15-min detection, 1-hr containment; P2: 1-hr detection, 4-hr containment',
        '[L4-GOV-01] IT Governance Framework — Board-approved IT strategy, ITSC constituted',
        '[L4-GOV-02] IT Steering Committee — meets quarterly, reviews BCP/DR, regulatory compliance',
        '[L4-AUD-01] IS Audit by CERT-In empanelled external auditor — annual mandatory',
        '[L4-AUD-02] IS Audit report to Board Audit Committee — tabled annually',
        '[L4-VCISO-01] CISO (or vCISO) with Board-level authority and reporting',
        '[L4-BCP-01] Business Continuity Plan tested annually — RTO/RPO defined and measured'
      ],
      lumiverse_services: 'C-SOC as a Service + vCISO + IS Audit (CERT-In) + IT Governance Framework + SIEM/SOAR + BCP/DR Testing + Forensics Retainer',
      gap_indicators: ['No C-SOC or SOC partner', 'No vCISO or CISO', 'No IS Audit evidence', 'No IT governance framework', 'No BCP testing evidence']
    }
  },

  // ── SERVICE PRICING (from Industries.xlsx) ────────────────────────────
  // USD pricing — multiply by ~83 for INR
  service_pricing: {
    'Web App VAPT (DAST)': {
      'Black Box - Micro/Small': '$1,490 – $1,970',
      'Black Box - Medium': '$2,325',
      'Black Box - Large': '$2,980',
      'Grey Box - Micro': '$1,730',
      'Grey Box - Medium': '$2,500',
      'Grey Box - Large': '$3,350'
    },
    'Web App VAPT (DAST+SAST Combined)': {
      'White Box - Micro': '$3,220',
      'White Box - Small': '$4,170',
      'White Box - Medium': '$4,525',
      'White Box - Large': '$6,200'
    },
    'Source Code Review (SAST)': {
      'Up to 10 repos': '$2,500',
      'Up to 20 repos': '$4,470',
      'Up to 50 repos': '$8,460',
      'Up to 100 repos': '$12,000'
    },
    'Mobile App VAPT (MAST)': {
      'Micro app': '$1,490 per binary',
      'Small app': '$1,790 per binary',
      'Medium app': '$2,500 per binary',
      'Large app': '$3,950 per binary'
    },
    'Cloud Security Assessment': {
      'AWS / Azure / GCP': '$5,000 each',
      'AWS Security Improvement Program': '$9,840',
      'AWS Configuration Audit': '$790'
    }
  },

  // ── BATTLE CARD — PRODUCT CATEGORIES (from BC Excel) ─────────────────
  product_categories: [
    'IAM (Identity Access Management)', 'PAM (Privileged Access Management)',
    'MDM (Mobile Device Management)', 'DLP (Data Loss Prevention)',
    'ITSM (IT Service Management)', 'EDR & XDR (Endpoint Detection)',
    'NAC (Network Access Control)', 'SIEM', 'SOAR',
    'Application Security', 'CSPM (Cloud Security Posture Mgmt)',
    'SAST (Static Application Security Testing)', 'API Security',
    'Anti Phishing', 'Email Security', 'Security Awareness Platform',
    'Secure Web Gateway (SWG)', 'GRC Solution', 'SD-WAN',
    'Dark Web and Threat Intelligence', 'Network Security',
    'BAS (Breach Attack Simulation)', 'Threat Hunting', 'HSM', 'Decoy/Deception'
  ],

  // ── ROI ARGUMENTS ─────────────────────────────────────────────────────
  roi_arguments: {
    vapt_web: {
      cost: 'Web App VAPT starts at $1,490 (₹1.24 lakh)',
      saves: 'Average India data breach cost: ₹17.9 crore (IBM 2024) | RBI penalty: up to ₹1 crore/day'
    },
    vapt_network: {
      cost: 'Network VAPT starts at ₹75,000',
      saves: 'One UCB fined ₹5.93 crore for not implementing cybersecurity protocols (FY25)'
    },
    mobile_vapt: {
      cost: 'Mobile VAPT starts at $1,490 per binary (₹1.24 lakh)',
      saves: 'Mobile banking fraud: ₹485 crore lost in FY25 | RBI mandatory per Level II UCB controls'
    },
    is_audit: {
      cost: 'IS Audit starts at ₹1.5 lakh',
      saves: 'RBI MD IT 2023 Para 30 violation → inspection finding → monetary penalty under BRA Section 46'
    },
    csoc: {
      cost: 'C-SOC as a Service starts at ₹40,000/month',
      saves: 'Detection without SOC: avg 207 days | With SOC: 21 days (IBM) | Level IV UCB mandatory per Annex IV'
    },
    vciso: {
      cost: 'vCISO starts at ₹25,000/month',
      saves: 'Full-time CISO salary: ₹30–80 lakh/year | vCISO mandatory from Level II+ UCBs (L2-CSO-01)'
    },
    ucb_packages: {
      'Level I': 'Network VAPT + DMARC + Policy + Awareness — starts ₹1.8 lakh',
      'Level II': 'Web+Mobile VAPT + CISO + DLP + SIEM — starts ₹4.5 lakh',
      'Level III': 'ATM + SWIFT + DC Security + PAM — starts ₹7 lakh',
      'Level IV': 'C-SOC + vCISO + IS Audit + IT Governance — starts ₹12 lakh/year'
    }
  },

  // ── OPEN SOURCE TOOLS FOR FREE DATA ───────────────────────────────────
  free_tools: {
    dns: 'Built-in Node DNS — SPF/DMARC/MX/Blacklist — unlimited, no key',
    ssl: 'crt.sh — SSL certs, subdomains, expiry — unlimited, no key',
    subdomains: 'HackerTarget — subdomain enum — 100/day, no key',
    virustotal: 'virustotal.com → API Keys → free 500/day — domain threat reputation',
    abuseipdb: 'abuseipdb.com → API → free 1000/day — IP abuse confidence score',
    censys: 'search.censys.io → API → free 250/month — open ports, SSL certs',
    shodan: 'shodan.io → free API key → 100 results/month — device/port scanning',
    whois: 'rdap.org (free, no key) — domain registration, registrant info',
    wappalyzer: 'api.wappalyzer.com → free plan → tech stack detection',
    securityheaders: 'securityheaders.com → free scan → HTTP security headers check',
    ssllabs: 'api.ssllabs.com → free → SSL grade (A to F), cert details'
  },

  // ── PASTE YOUR PDF DATA HERE ──────────────────────────────────────────
  custom_regulatory_notes: [],
  custom_compliance_criteria: [],
  custom_service_notes: []
};

// ── FORMAT FOR AI PROMPT ──────────────────────────────────────────────
function buildKnowledgeContext(industry, mode) {
  const ind = (industry||'').toLowerCase();
  const isUCB  = /cooperative|ucb|urban co/.test(ind) || mode === 'bank';
  const isBank = /bank|nbfc|payment/.test(ind) || mode === 'bank';

  const L = ['\n=== LUMIVERSE KNOWLEDGE BASE ===\n'];

  L.push('LUMIVERSE CREDENTIALS (use in every script for authority):');
  KNOWLEDGE_BASE.credentials.slice(0,6).forEach(c => L.push(`  • ${c}`));

  L.push('\nROI ARGUMENTS (use for price objections):');
  const roi = KNOWLEDGE_BASE.roi_arguments;
  // Universal ROI args — no RBI mention for non-BFSI
  L.push(`  Web VAPT: ${roi.vapt_web.cost} | Risk: avg data breach costs ₹17.9 crore (IBM 2024)`);
  L.push(`  Network VAPT: ${roi.vapt_network.cost} | Risk: open ports found by attackers within 15 min`);
  L.push(`  C-SOC: ${roi.csoc.cost} | Risk: avg breach detection time 197 days without monitoring`);
  L.push(`  vCISO: ${roi.vciso.cost} | Risk: no CISO = no security strategy, regulators take note`);
  L.push(`  IS Audit: ${roi.is_audit.cost} | Risk: CERT-In 6-hr reporting mandate — all entities`);
  if (isBank || isUCB) {
    L.push(`  [BANK ONLY] UCB packages: ${JSON.stringify(roi.ucb_packages||{})}`);
    L.push(`  [BANK ONLY] RBI penalty risk: up to ₹1 crore/day non-compliance`);
  }

  if (isUCB || isBank) {
    L.push('\nUCB LEVEL FRAMEWORK — IDENTIFY LEVEL, THEN MAP GAPS:');
    Object.entries(KNOWLEDGE_BASE.ucb_levels).forEach(([level, data]) => {
      L.push(`\n  [${level} — ${data.total_controls} controls${data.cumulative?', cumulative '+data.cumulative:''}]`);
      L.push(`  Applicable to: ${data.applicable_to}`);
      L.push(`  Gap indicators: ${data.gap_indicators.join(' | ')}`);
      L.push(`  Top CRITICAL controls (cite control ID in script):`);
      data.critical_controls.slice(0,5).forEach(c => L.push(`    ${c.slice(0,100)}`));
      L.push(`  Lumiverse services: ${data.lumiverse_services}`);
      L.push(`  Packages: ${KNOWLEDGE_BASE.roi_arguments.ucb_packages[level.replace('_',' ')] || ''}`);
    });
  }

  if (KNOWLEDGE_BASE.custom_regulatory_notes.length) {
    L.push('\nCUSTOM NOTES (from your documents):');
    KNOWLEDGE_BASE.custom_regulatory_notes.forEach(n => L.push(`  • ${n}`));
  }

  L.push('\n=== END KNOWLEDGE BASE ===\n');
  return L.join('\n');
}

module.exports = { KNOWLEDGE_BASE, buildKnowledgeContext };
