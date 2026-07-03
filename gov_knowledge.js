// ═══════════════════════════════════════════════════════════════════════
// GOV SECURITY KNOWLEDGE BASE
// Sources: CERT-In, MHA C&IS, CSK, MeitY, NCSP, NPCI, RBI
// Scraped: March 2026
// ═══════════════════════════════════════════════════════════════════════

const GOV_KNOWLEDGE = {

  // ── CERT-In (Indian Computer Emergency Response Team) ────────────────
  cert_in: {
    authority: 'CERT-In under Section 70B IT Act 2000 — MeitY',
    url: 'https://www.cert-in.org.in',
    mandatory_for: 'ALL organizations in India including banks, NBFCs, PSOs, IT companies, health, telecom',
    key_directives: [
      { ref:'CERT-In Direction Apr 28 2022', req:'Cyber incidents reported within 6 HOURS of detection', penalty:'Criminal violation under IT Act Section 70B', applies:'ALL entities' },
      { ref:'CERT-In Direction Apr 28 2022', req:'ICT system logs retained for 180 days on India-based servers', penalty:'IT Act violation', applies:'ALL entities' },
      { ref:'CERT-In Direction Apr 28 2022', req:'NTP (Network Time Protocol) synchronization with NTP.GOV.IN', penalty:'IT Act violation', applies:'ALL entities' },
      { ref:'CERT-In Direction Apr 28 2022', req:'VPN/Cloud provider subscriber data retained for 5 YEARS', penalty:'IT Act violation', applies:'VPN/Cloud providers' },
      { ref:'CERT-In Audit Policy Jul 2025', req:'282-control audit framework mandatory for CERT-In empanelled auditors — CVSS+EPSS scoring mandatory, OWASP references, AI/blockchain scope', penalty:'Empanelment revocation', applies:'CERT-In empanelled auditors' },
      { ref:'CERT-In Gov Entity Guidelines', req:'CISO nominated and details provided to CERT-In — mandatory', penalty:'Non-compliance with GoI mandate', applies:'All government entities and PSUs' },
      { ref:'CERT-In Gov Entity Guidelines', req:'Third-party security audit at least ANNUALLY — CERT-In empanelled auditors preferred', penalty:'Audit finding', applies:'Government entities' },
      { ref:'CERT-In Gov Entity Guidelines', req:'Internal IS audit at least every 6 MONTHS', penalty:'Internal control failure', applies:'Government entities' }
    ],
    sales_triggers: [
      'CERT-In audited 9,700+ entities in FY25 — enforcement ramping up rapidly',
      'India 13.7% of global cyber incidents in 2024 — 369 million malware detections',
      '₹11,333 crore cybercrime losses in first 9 months of 2024 alone',
      'Projections: ₹1.2 lakh crore cybercrime losses in 2025',
      'Healthcare sector top target: 21.82% of all attacks in 2024',
      '702 cyber threats every minute targeting Indian organizations',
      'CERT-In empanelled auditor required for ALL regulatory IS audits (RBI/SEBI/IRDAI)'
    ]
  },

  // ── MHA Cyber & Information Security Division ─────────────────────────
  mha_cis: {
    authority: 'Ministry of Home Affairs — Cyber & Information Security (C&IS) Division',
    url: 'https://www.mha.gov.in/en/divisionofmha/cyber-and-information-security-cis-division',
    mandate: 'Policy on cybercrime, cyber security of critical infrastructure, I4C (Indian Cyber Crime Coordination Centre)',
    i4c: {
      full_name: 'Indian Cyber Crime Coordination Centre',
      function: 'Coordinate cybercrime investigation across states, share intelligence, facilitate takedown of fraudulent domains',
      helpline: '1930 — National Cyber Crime Helpline',
      portal: 'cybercrime.gov.in'
    },
    sales_triggers: [
      'I4C processes 10,000+ cyber complaints daily — your clients\' employees are targets',
      'MHA National Cyber Crime Helpline 1930 — banks must have internal process to report + cooperate',
      'BEC (Business Email Compromise) is top financial cyber crime reported to I4C',
      'Lumiverse has solved 650+ cases with Maharashtra Police — direct law enforcement experience'
    ]
  },

  // ── Cyber Swachhta Kendra ─────────────────────────────────────────────
  csk: {
    authority: 'Cyber Swachhta Kendra — Botnet Cleaning & Malware Analysis Centre, operated by CERT-In',
    url: 'https://www.csk.gov.in',
    mandate: 'Detect botnet infections, notify and help clean systems, free security tools for Indian organizations',
    free_tools: ['Free Bot Removal Tools', 'USB Pratirodh', 'AppSamvid (application whitelist)', 'M-Kavach (mobile security)', 'eScan Antivirus'],
    sales_triggers: [
      'CSK detected active botnets across Indian banks in 2024 — ISP-notified infections',
      'Free security tools from CSK are NOT sufficient for RBI/SEBI compliance',
      'Many UCBs believe CSK tools = compliance — this is factually wrong',
      'Active botnet infection + no SOC = average 207 days to detect (IBM 2024)'
    ]
  },

  // ── National Cyber Security Policy ───────────────────────────────────
  ncsp: {
    ref: 'National Cyber Security Policy 2013 (NCSP) — DeitY/MeitY',
    status: 'Active framework — last updated 2013, enhanced by subsequent sector regulations',
    five_objectives: [
      'Create a secure computing environment for individuals, businesses, and government',
      'Protect Critical Information Infrastructure (CII) — power, banking, telecom, defense',
      'Build national capacity: train 500,000 cybersecurity professionals',
      'Enable public-private partnerships for cyber security',
      'Develop indigenous security products and reduce import dependence'
    ],
    cii_sectors: ['Power & Energy', 'Banking, Financial Services & Insurance', 'Telecom', 'Transport', 'Government', 'Space', 'Defence'],
    sales_trigger: 'BFSI is designated Critical Information Infrastructure — banks face NCIIPC oversight + CERT-In mandates + RBI requirements simultaneously'
  },

  // ── NCIIPC ────────────────────────────────────────────────────────────
  nciipc: {
    full_name: 'National Critical Information Infrastructure Protection Centre',
    authority: 'NTRO under Prime Minister\'s Office — Section 70A IT Act',
    mandate: 'Protect Critical Information Infrastructure (CII) — banks, power, telecom, defense',
    applies_to_bfsi: 'All scheduled banks, large NBFCs, PSOs are considered CII entities',
    sales_trigger: 'NCIIPC CII designation means banks face TWO layers of oversight: NCIIPC (national) + RBI (sector). Non-compliance with RBI = automatic NCIIPC risk.'
  },

  // ── MeitY ─────────────────────────────────────────────────────────────
  meity: {
    full_name: 'Ministry of Electronics and Information Technology',
    key_mandates: [
      'DPDP Act 2023 — Digital Personal Data Protection — ₹250 crore max penalty',
      'IT Act 2000 + Amendment 2008 — legal framework for cyber crimes and compliance',
      'CERT-In Directions under Section 70B IT Act',
      'Cyber Hygiene Guidelines for organizations',
      'GovStack — IT infrastructure security for government entities'
    ],
    dpdp_status: 'DPDP Act 2023 enacted. Rules being finalized. Data Protection Board being constituted. Enforcement imminent 2025-26.',
    sales_trigger: 'MeitY oversees DPDP enforcement — every bank, NBFC, insurer processing Indian personal data is covered — ₹250 crore penalty per violation'
  },

  // ── NPCI (National Payments Corporation of India) ─────────────────────
  npci: {
    authority: 'NPCI under RBI oversight',
    cyber_requirements: [
      'All NPCI member banks must undergo NPCI cyber audit annually',
      'UPI — PCI-DSS compliance mandatory for all UPI participants',
      'Aadhaar-enabled Payment System (AePS) — additional UIDAI STQC audit',
      'IMPS/RTGS/NEFT participants — RBI CSF 2016 + MD IT 2023 compliance',
      'FASTag — network security and anti-fraud controls mandatory'
    ],
    sales_trigger: 'NPCI UPI fraud: ₹485 crore in FY25. All UPI member banks must demonstrate anti-fraud controls. Lumiverse provides NPCI-aligned security assessments.'
  },

  // ── UIDAI (Aadhaar) ───────────────────────────────────────────────────
  uidai: {
    full_name: 'Unique Identification Authority of India',
    cyber_requirements: [
      'AUA/KUA (Aadhaar-enabled authentication): STQC audit mandatory',
      'Aadhaar data — highest classification, stored only on UIDAI servers',
      'Banks using Aadhaar for KYC must comply with UIDAI security framework',
      'Authentication logs retained per UIDAI mandate'
    ],
    sales_trigger: 'Any bank doing Aadhaar-based KYC must pass UIDAI AUA/KUA audit — Lumiverse provides this assessment.'
  },

  // ── INDIA CYBER STATS 2024-25 ─────────────────────────────────────────
  threat_stats: {
    malware: '369 million malware detections in India in 2024 (8.44 million endpoints)',
    rate: '702 cyber threats per minute targeting Indian organizations',
    global_share: 'India accounts for 13.7% of global cyber incidents',
    losses_2024: '₹11,333 crore cybercrime losses in first 9 months of 2024',
    projection_2025: '₹1.2 lakh crore projected losses in 2025',
    top_target: 'Healthcare: 21.82% of attacks (up from 15% in 2023)',
    bfsi_rank: 'BFSI consistently top 2 targeted sector',
    ransomware: 'Ransomware shifting to data theft without encryption — no backups don\'t help',
    cert_in_audits: 'CERT-In audited 9,700+ entities in FY25 — enforcement at record level',
    upi_fraud: '₹485 crore UPI fraud in FY25 | ₹2,145 crore cumulative since FY22',
    source: 'India Cyber Threat Report 2025 | RBI Annual Report 2024-25 | I4C data'
  }
};

// ── BUILD CONTEXT FOR AI PROMPT ────────────────────────────────────────
function buildGovContext(industry, mode) {
  const L = ['\n=== GOVERNMENT SECURITY KNOWLEDGE (use these facts in scripts) ===\n'];

  // Threat stats — filter banking-specific for non-BFSI
  const isBankInd = /bank|nbfc|payment|fintech|finance|cooperative|ucb|sebi|irdai/.test(ind) || mode==='bank';
  L.push('INDIA CYBER THREAT REALITY 2024-25:');
  const s = GOV_KNOWLEDGE.threat_stats;
  L.push(`  • ${s.malware}`);
  L.push(`  • ${s.rate}`);
  L.push(`  • ${s.losses_2024}`);
  L.push(`  • ${s.cert_in_audits}`);
  if (isBankInd) {
    L.push(`  • ${s.upi_fraud}`);
    L.push(`  • ${s.projection_2025}`);
  }
  L.push(`  Source: ${s.source}`);

  // CERT-In mandates — applies to everyone
  L.push('\nCERT-In MANDATORY REQUIREMENTS (ALL organizations, no exemption):');
  GOV_KNOWLEDGE.cert_in.key_directives.forEach(d => {
    L.push(`  [${d.ref}] ${d.req}`);
    L.push(`    → Penalty: ${d.penalty}`);
  });

  // Sales triggers
  L.push('\nCERT-In SALES TRIGGERS:');
  GOV_KNOWLEDGE.cert_in.sales_triggers.forEach(t => L.push(`  • ${t}`));

  // MHA/I4C
  L.push('\nMHA I4C (Indian Cyber Crime Coordination Centre):');
  L.push(`  Helpline: ${GOV_KNOWLEDGE.mha_cis.i4c.helpline} | Portal: ${GOV_KNOWLEDGE.mha_cis.i4c.portal}`);
  GOV_KNOWLEDGE.mha_cis.sales_triggers.forEach(t => L.push(`  • ${t}`));

  // NCIIPC for banks
  const ind = (industry||'').toLowerCase();
  if (/bank|nbfc|payment|fintech|finance/.test(ind) || mode==='bank') {
    L.push('\nNCIIPC — Critical Information Infrastructure:');
    L.push(`  ${GOV_KNOWLEDGE.nciipc.sales_trigger}`);
    L.push('\nNPCI REQUIREMENTS:');
    GOV_KNOWLEDGE.npci.cyber_requirements.forEach(r => L.push(`  • ${r}`));
    L.push(`  Trigger: ${GOV_KNOWLEDGE.npci.sales_trigger}`);
  }

  // DPDP for all
  L.push('\nDPDP ACT 2023 (MeitY):');
  L.push(`  ${GOV_KNOWLEDGE.meity.dpdp_status}`);
  L.push(`  Trigger: ${GOV_KNOWLEDGE.meity.sales_trigger}`);

  L.push('\n=== END GOV KNOWLEDGE ===\n');
  return L.join('\n');
}

module.exports = { GOV_KNOWLEDGE, buildGovContext };
