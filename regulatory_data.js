// ═══════════════════════════════════════════════════════════════════════
// LUMIVERSE REGULATORY INTELLIGENCE — LIVE DATA
// Sources: RBI rbi.org.in | SEBI sebi.gov.in | IRDAI irdai.gov.in
// Scraped & compiled: March 2026
// ═══════════════════════════════════════════════════════════════════════

// ── REAL RBI PENALTY DATA ────────────────────────────────────────────
const RBI_ENFORCEMENT = {
  fy2025: { penalties: 353, total: '₹54.78 crore', top_violation: 'Cybersecurity framework non-compliance' },
  notable: [
    { entity:'Cooperative Bank (Western India)', amount:'₹5.93 crore', reason:'Cybersecurity protocols NOT implemented', date:'FY25' },
    { entity:'IndusInd Bank Ltd', amount:'₹27.3 lakh', reason:'Deposit account compliance', date:'Dec 2024' },
    { entity:'X10 Financial Services', amount:'CoR CANCELLED', reason:'Outsourcing core functions without due diligence', date:'Jan 2025' },
    { entity:'Manappuram Finance', amount:'Monetary penalty', reason:'KYC verification failure', date:'Dec 2024' }
  ],
  upi_fraud: { fy25_loss:'₹485 crore', fy25_incidents:'6.32 lakh', cumulative_loss:'₹2,145 crore', cumulative_incidents:'27 lakh' },
  source:'RBI Annual Report 2024-25'
};

// ── RBI IT DIRECTIONS 2023 ────────────────────────────────────────────
const RBI_IT_DIRECTIONS_2023 = {
  ref: 'RBI/2023-24/107 | DoS.CO.CSITEG/SEC.7/31.01.015/2023-24',
  name: 'Master Direction on IT Governance, Risk, Controls and Assurance Practices',
  effective: 'April 1, 2024',
  url: 'https://rbi.org.in/scripts/BS_ViewMasDirections.aspx?id=12562',
  applies_to: ['Scheduled Commercial Banks','Small Finance Banks','Payment Banks','NBFCs (Upper/Middle/Top Layer)','Credit Information Companies','EXIM Bank','NABARD','NHB','SIDBI'],
  chapters: {
    'Chapter II': 'IT Governance — Board must have IT Strategy Committee',
    'Chapter III': 'IT Infrastructure — patch mgmt, access controls, audit trails, cryptography',
    'Chapter IV': 'IT Risk — VAPT, IS audit, cyber incident response, info sec policy',
    'Chapter V': 'Business Continuity — BCP/DR mandatory, tested annually',
    'Chapter VI': 'IS Audit — CERT-In empanelled auditor mandatory'
  },
  mandates: [
    { sec:'Section 5', title:'Board IT Strategy Committee', req:'Board must constitute IT Strategy Committee — review IT strategy quarterly', gap:'No IT committee or board-level IT oversight', service:'vCISO + Managed Compliance', penalty:'RBI inspection finding → regulatory censure' },
    { sec:'Section 10', title:'Third-Party IT Risk', req:'Bank liable for all third-party vendor IT security — due diligence mandatory before and during engagement', gap:'Using IT vendors without security due diligence', service:'Third Party Risk Assessment', penalty:'X10 Financial CoR cancelled for this exact failure (Jan 2025)' },
    { sec:'Section 13', title:'Patch & Change Management', req:'Vulnerability patches within defined timelines — critical patches within 30 days', gap:'No patch management process, outdated systems', service:'Vulnerability Assessment + C-SOC', penalty:'RBI inspection finding' },
    { sec:'Section 19', title:'Access Controls & PAM', req:'Privileged Access Management mandatory — least privilege, quarterly access reviews', gap:'No PAM solution, shared admin credentials', service:'PAM + Network VAPT', penalty:'Part of cybersecurity non-compliance — ₹5.93 crore precedent' },
    { sec:'Section 24', title:'Cyber Security Policy', req:'Board-approved Cyber Security Policy — separate from IT policy — annual review', gap:'No board-approved cybersecurity policy', service:'vCISO + Policy Development', penalty:'Supervisory action' },
    { sec:'Section 25', title:'Risk Assessment', req:'Annual IT/cyber risk assessment — cloud risk, third-party risk, emerging tech risk included', gap:'No formal risk assessment process', service:'IT Risk Assessment + GAP Assessment', penalty:'PCA framework for NBFCs' },
    { sec:'Section 26', title:'VAPT MANDATORY', req:'Vulnerability Assessment & Penetration Testing by CERT-In EMPANELLED vendor — annually and after every major change. Scope: network, systems, apps, APIs', gap:'No VAPT, or VAPT by non-CERT-In vendor', service:'VAPT (Network/Web/Mobile/API/Cloud)', penalty:'₹1 crore per day per violation under Banking Regulation Act Section 46' },
    { sec:'Section 27', title:'Cyber Incident Response', req:'IRP mandatory — test annually — report breach to RBI within 6 hours of discovery', gap:'No IRP, no breach reporting process', service:'Digital Forensics + IR + Managed Compliance', penalty:'Non-reporting is separate violation with additional penalty' },
    { sec:'Section 28-29', title:'BCP & DR', req:'Business Continuity Plan + Disaster Recovery — test at least annually — RTO/RPO defined', gap:'No BCP/DR or untested plan', service:'BCMS + IS Audit', penalty:'RBI inspection finding' },
    { sec:'Section 30', title:'IS Audit MANDATORY', req:'Annual IS Audit by CERT-In EMPANELLED EXTERNAL auditor — cannot be internal team', gap:'Self-audit or non-CERT-In auditor', service:'IS Audit (EDP Audit)', penalty:'Regulatory action — RBI annual inspection report' }
  ]
};

// ── RBI CYBER RESILIENCE FOR PSOs 2024 ───────────────────────────────
const RBI_PSO_2024 = {
  ref: 'RBI Master Direction on Cyber Resilience & Digital Payment Security Controls, July 2024',
  applies_to:['Payment Aggregators','Card Payment Networks','PPI Issuers','White Label ATM Operators','Immediate Payment Service Operators'],
  mandates: [
    { title:'PCI-DSS v4.0 Mandatory', req:'All payment processors must maintain PCI-DSS v4.0 — annual audit', penalty:'RBI may suspend PA/PG license', service:'PCI-DSS Compliance + VAPT' },
    { title:'Cyber Policy', req:'Board-approved cyber policy and annual risk assessment', penalty:'RBI enforcement', service:'vCISO + Policy' },
    { title:'VAPT', req:'VAPT for all payment systems quarterly for critical, annually for others', penalty:'Enforcement action', service:'VAPT (API/Web/Mobile)' },
    { title:'Incident Reporting', req:'Cyber incident to RBI CSITE within 6 hours of discovery', penalty:'Separate violation for late reporting', service:'IR + Forensics' }
  ]
};

// ── SEBI CSCRF 2024 ───────────────────────────────────────────────────
const SEBI_CSCRF = {
  ref: 'SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113',
  name: 'Cybersecurity and Cyber Resilience Framework (CSCRF)',
  issued: 'August 20, 2024',
  latest_clarification: 'SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2025/119 dated August 28, 2025',
  goals: ['Anticipate','Withstand','Contain','Recover','Evolve'],
  functions: ['Governance','Identify','Protect','Detect','Respond','Recover'],
  applies_to:['Stock Exchanges','Clearing Corporations','Depositories','Stock Brokers','Depository Participants','Mutual Funds/AMCs','Portfolio Managers','RTAs','KRAs','Investment Advisors','Research Analysts','Alternative Investment Funds','Merchant Bankers'],
  entity_categories: {
    MII: { entities:['NSE','BSE','MCX','NSDL','CDSL','NSE Clearing','ICCL'], deadline:'January 1, 2025 — PAST DUE', requirements:['ISO 27001 MANDATORY','SOC + half-yearly efficacy report','Red teaming annually','VAPT post every major release + quarterly','CERT-In IS Audit annually','CISO reports directly to MD/CEO','Risk Management Committee mandatory'] },
    Qualified_RE: { threshold:'Large brokers/DPs/AMCs based on client count/volume/AUM', deadline:'August 31, 2025 — PAST DUE', requirements:['ISO 27001 mandatory','SOC mandatory','Red teaming annual','VAPT + IS Audit','CISO mandatory','Cyber risk framework'] },
    Mid_Size_RE: { deadline:'August 31, 2025 — PAST DUE', requirements:['Cyber risk framework','VAPT','IS Audit','SOC or Market-SOC enrollment','Incident reporting to exchange'] },
    Small_RE: { deadline:'August 31, 2025 — PAST DUE', requirements:['Basic cyber policy','Baseline controls (CIS Controls Level 1)','Market-SOC enrollment','Incident reporting'] },
    Self_Certification_RE: { deadline:'August 31, 2025 — PAST DUE', requirements:['Baseline security','Annual self-certification','Market-SOC enrollment'] }
  },
  mandates: [
    { ref:'GV.PO-1', title:'Cybersecurity & Resilience Policy', req:'Board-approved policy — annual review — communicated to all employees', gap:'No board-approved cyber policy', service:'vCISO + Policy', penalty:'SEBI enforcement' },
    { ref:'ID.AM-2', title:'Asset Management', req:'Complete inventory: all physical devices, digital assets, URLs, APIs, cloud services', gap:'No asset register', service:'IS Audit + Asset Discovery', penalty:'CSCRF non-compliance' },
    { ref:'PR.AC-1', title:'Access Control & Authentication', req:'Authentication policy + log collection + MFA for critical systems', gap:'No MFA, no access logs', service:'PAM + C-SOC + Network VAPT', penalty:'SEBI inspection' },
    { ref:'PR.IP-12', title:'VAPT', req:'VAPT mandatory after EVERY major release + periodic — all critical systems, APIs, cloud', gap:'No VAPT or non-CERT-In vendor', service:'VAPT (Web/API/Cloud/Mobile)', penalty:'SEBI enforcement — market operations can be restricted' },
    { ref:'PR.IP-3', title:'ISO 27001 MANDATORY', req:'ISO 27001 MANDATORY for MIIs and Qualified REs — not optional', gap:'No ISO 27001 certification', service:'ISO 27001 (ISMS) Implementation', penalty:'Cannot qualify as Qualified RE — SEBI action' },
    { ref:'DE.CM-1', title:'SOC Mandatory', req:'SOC mandatory for ALL REs — own or Market-SOC (NSE/BSE) subscription — efficacy report submitted periodically', gap:'No SOC, not enrolled in Market-SOC', service:'C-SOC as a Service + SIEM', penalty:'SEBI supervisory action' },
    { ref:'RS.RP-1', title:'Red Teaming', req:'Annual red team exercises mandatory for MIIs and Qualified REs — adversarial simulation, not standard VAPT', gap:'Never done red teaming', service:'Red Team + Purple/Blue Team Assessment', penalty:'CSCRF non-compliance' },
    { ref:'RS.CO-2', title:'Incident Reporting', req:'All cyber incidents reported via SEBI incident reporting portal — to respective authority (exchange/depository)', gap:'No incident reporting process', service:'IR + Managed Compliance', penalty:'Separate SEBI violation' },
    { ref:'RC.RP-1', title:'IS Audit', req:'Annual IS Audit by CERT-In empanelled organization — auditors checklist submitted to SEBI/exchange', gap:'No CERT-In empanelled auditor', service:'IS Audit + CISA Audit', penalty:'SEBI inspection finding' },
    { ref:'GV.RR-1', title:'CISO Mandatory', req:'CISO mandatory — seniority equivalent to CTO/CIO — reports directly to MD/CEO for MIIs/Qualified REs', gap:'No CISO', service:'Virtual CISO (vCISO)', penalty:'Board-level accountability' },
    { ref:'PR.IP-11', title:'API Security', req:'Rate limiting + throttling + proper auth on ALL APIs — endpoint security mandatory', gap:'APIs without authentication or rate limiting', service:'API VAPT + Source Code Audit', penalty:'Critical VAPT finding' }
  ]
};

// ── IRDAI CYBER GUIDELINES 2023 ───────────────────────────────────────
const IRDAI_GUIDELINES = {
  ref: 'IRDAI Information and Cyber Security Guidelines, April 24, 2023',
  amended: 'March 24, 2025 — cyber incident & crisis preparedness provisions added',
  url: 'https://irdai.gov.in/documents/37343/366029/IRDAI+CS+Guidelines+2023.pdf',
  applies_to:['Life Insurance Companies','General Insurance Companies','Health Insurance Companies','Foreign Reinsurance Branches (FRBs)','Insurance Brokers','Corporate Agents','TPAs','Web Aggregators','Insurance Marketing Firms','Insurance Repositories','Common Service Centers','Insurance Information Bureau of India'],
  excludes:['Individual insurance agents','Micro-insurance agents','Point-of-sale persons','Individual surveyors'],
  entity_classification: {
    Tier1_Insurers: { basis:'All insurers + FRBs', requirements:'Full IRDAI CS Guidelines + VAPT + IS Audit + SOC + CISO + IRP + Data Localization' },
    Tier2_Intermediaries_High: { basis:'Brokers with >₹50 crore revenue or access to insurer DB', requirements:'Full framework applicable' },
    Tier3_Intermediaries_Medium: { basis:'Brokers ₹5-50 crore revenue', requirements:'Partial framework — IS Audit + basic controls' },
    Tier4_Self_Certification: { basis:'No access to insurer DB + physical records only', requirements:'Annual self-certification to insurer' }
  },
  mandates: [
    { title:'Board-Approved ICSP', req:'Information and Cyber Security Policy (ICSP) — board approved — annual review by CISO — presented to audit committee', gap:'No ICSP or not board-approved', service:'vCISO + Policy Development', penalty:'IRDAI enforcement, license risk' },
    { title:'CISO Mandatory', req:'CISO mandatory — IS Team comprising CISO — reports to CRO — CRO assumes CISO role if critical decisions needed', gap:'No CISO appointed', service:'Virtual CISO (vCISO)', penalty:'IRDAI inspection finding' },
    { title:'Risk Management Committee', req:'ISRMC (Information Security Risk Management Committee) mandatory — periodic review of IS risks', gap:'No ISRMC', service:'vCISO + Managed Compliance', penalty:'IRDAI governance finding' },
    { title:'VAPT Mandatory', req:'Periodic Vulnerability Assessment & Penetration Testing + annual independent IS Audit — all IT systems including web portals and mobile apps', gap:'No VAPT or infrequent VAPT', service:'VAPT (Web/Mobile/Network) + IS Audit', penalty:'IRDAI supervisory action' },
    { title:'IS Audit Mandatory', req:'Annual independent IS Audit by CERT-In empanelled firm — audit report submitted to IRDAI within 90 days of FY end OR 30 days from audit completion (whichever earlier)', gap:'No IS Audit or late submission', service:'IS Audit', penalty:'IRDAI enforcement action' },
    { title:'Data Localization', req:'Primary data must be stored in India — ICT infrastructure logs stored for 180 days rolling', gap:'Using foreign cloud without data localization', service:'Data Localization Audit + DPDP Compliance', penalty:'IRDAI + DPDP Act ₹250 crore' },
    { title:'SOC / 24x7 Monitoring', req:'24x7 monitoring of all ICT systems — SOC logs retained 180 days — end-to-end monitoring mandatory', gap:'No SOC or incomplete monitoring', service:'C-SOC as a Service', penalty:'IRDAI inspection' },
    { title:'Incident Reporting — 6 Hours', req:'Cyber incident → IRDAI within 6 hours + CERT-In within 6 hours — crisis management committee mandatory', gap:'No IRP or reporting process', service:'IR + Forensics + Managed Compliance', penalty:'Separate IRDAI violation for late reporting (Mar 2025 amendment)' },
    { title:'Pre-Empanelled Forensic Experts', req:'Insurers must pre-empanel forensic experts BEFORE an incident occurs — separate vendor from risk identifier', gap:'No forensic retainer', service:'Digital Forensics (Lumiverse pre-empanelment)', penalty:'Investigation delays → greater damage + IRDAI action' },
    { title:'Third-Party Vendor Control', req:'All vendors with access to insurer systems must comply with ICSP — regular audits of vendors', gap:'Vendors not security audited', service:'Third Party Risk Assessment + Vendor VAPT', penalty:'Insurer liable for vendor breaches' },
    { title:'Social Media & Acceptable Use', req:'Formal acceptable use policy for social media — personal use cannot be attributed to organisation', gap:'No acceptable use policy', service:'vCISO + Policy', penalty:'Governance finding' }
  ]
};

// ── DPDP ACT 2023 ─────────────────────────────────────────────────────
const DPDP_ACT = {
  ref: 'Digital Personal Data Protection Act, 2023 — Enacted August 11, 2023',
  status: 'Act enacted. Rules being finalized. DPDP Board being constituted. Enforcement imminent.',
  penalties: { data_breach:'₹250 crore', breach_notification_failure:'₹200 crore', children_data:'₹200 crore', inadequate_security:'₹250 crore', default:'Up to ₹50 crore' },
  applies_to:'ALL organizations processing personal data of Indian citizens — no industry, no size exemption',
  key_obligations: [
    { title:'Security Safeguards', sec:'Section 8(4)', req:'Reasonable security safeguards to prevent data breach — technical and organizational measures mandatory' },
    { title:'Breach Notification', sec:'Section 8(6)', req:'Notify Data Protection Board AND data principal upon breach — 72 hours' },
    { title:'Data Retention', sec:'Section 8(7)', req:'Delete personal data when purpose fulfilled — no indefinite retention' },
    { title:'Consent', sec:'Section 6', req:'Free, specific, informed, unconditional consent before processing personal data' },
    { title:'Children Data', sec:'Section 9', req:'Verifiable parental consent for processing data of children under 18 — no targeted advertising' }
  ]
};

// ── TRIGGER LIBRARY ───────────────────────────────────────────────────
const TRIGGERS = {
  bank: [
    { urgency:'CRITICAL', trigger:'RBI IT Directions non-compliance since April 2024', line:`RBI IT Directions 2023 have been in force since April 1, 2024 — over a year of mandatory compliance. In FY25 alone, RBI penalized 353 institutions totaling ₹54.78 crore, with cybersecurity framework failure as the top violation. The highest single penalty — ₹5.93 crore — was imposed on a cooperative bank specifically for not implementing cybersecurity protocols.`, service:'VAPT + IS Audit + C-SOC' },
    { urgency:'CRITICAL', trigger:'VAPT must be by CERT-In empanelled vendor specifically', line:`Section 26 of RBI IT Directions 2023 mandates VAPT by a CERT-In EMPANELLED vendor — not any vendor, not your internal team. If your current VAPT provider is not on CERT-In's empanelment list, your compliance is invalid regardless of how thorough the report was.`, service:'CERT-In Empanelled VAPT' },
    { urgency:'CRITICAL', trigger:'IS Audit must be external CERT-In auditor', line:`Section 30 explicitly mandates IS Audit by an EXTERNAL CERT-In empanelled auditor annually. Internal teams cannot self-certify. Self-audit constitutes non-compliance — exactly the kind of design failure RBI's enforcement report identified across penalized institutions.`, service:'IS Audit (CERT-In Empanelled)' },
    { urgency:'HIGH', trigger:'Third-party vendor liability — no escape', line:`RBI Section 10 holds your institution fully liable for your IT vendor's security failures. X10 Financial had its Certificate of Registration cancelled in January 2025 for outsourcing core functions without adequate due diligence. Your vendor's security is your regulatory risk.`, service:'Third Party Risk Assessment + Vendor VAPT' },
    { urgency:'HIGH', trigger:'UPI fraud epidemic — regulators watching closely', line:`UPI-related frauds cost Indian banks ₹485 crore across 6.32 lakh incidents in FY25 alone. Cumulative losses since FY22 stand at ₹2,145 crore. RBI is actively tightening monitoring requirements — banks without real-time fraud detection and C-SOC are the next targets.`, service:'C-SOC + Anti-Fraud Monitoring + SIEM' },
    { urgency:'HIGH', trigger:'Breach reporting — 6 hour window', line:`Section 27 mandates cyber breach reporting to RBI within 6 hours of discovery. Not 6 hours after containment — 6 hours after discovery. Without a documented Incident Response Plan tested annually, you cannot meet this window and face a compounded penalty for non-reporting.`, service:'IRP + Digital Forensics + IR' },
    { urgency:'HIGH', trigger:'Zero Trust Architecture — RBI 2025 guidance', line:`RBI's 2025 cybersecurity mandates explicitly require banks to move toward Zero Trust Architecture. Perimeter-based security — firewalls and VPNs — is no longer sufficient per RBI's framework. Banks still running perimeter-only security are architecturally non-compliant.`, service:'Network VAPT + ZTA Assessment + C-SOC' }
  ],
  sebi: [
    { urgency:'CRITICAL', trigger:'ALL SEBI CSCRF deadlines have passed', line:`Every SEBI CSCRF compliance deadline has passed as of March 2026 — MIIs from January 1 2025, all others from August 31 2025. If you have not completed VAPT, implemented SOC, and engaged a CERT-In IS Auditor — you are currently in active non-compliance under Circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2025/119.`, service:'CSCRF Gap Assessment + VAPT + IS Audit' },
    { urgency:'CRITICAL', trigger:'ISO 27001 MANDATORY — not optional', line:`SEBI CSCRF explicitly classifies ISO 27001 as MANDATORY for MIIs and Qualified REs — not a best practice, not a recommendation. Your ISO status directly determines your SEBI compliance posture and your ability to operate as a regulated entity.`, service:'ISO 27001 (ISMS) Implementation' },
    { urgency:'HIGH', trigger:'SOC for every entity including small brokers', line:`SEBI CSCRF mandates SOC for ALL regulated entities — including small brokers. If you cannot afford your own SOC, SEBI has mandated Market-SOC through NSE and BSE where you can enroll. Not enrolling is itself a compliance violation.`, service:'C-SOC as a Service + Market-SOC onboarding' },
    { urgency:'HIGH', trigger:'Red teaming — most brokers have never done it', line:`CSCRF Reference RS.RP-1 mandates annual red team exercises for MIIs and Qualified REs — full adversarial simulation reflecting real-world attack conditions. This is fundamentally different from standard VAPT. Most brokers have never undergone a red team exercise and would fail one.`, service:'Red Team + Purple/Blue Team Assessment' },
    { urgency:'HIGH', trigger:'API security explicitly mandated', line:`CSCRF Reference PR.IP-11 explicitly mandates API security — rate limiting, throttling, proper authentication on ALL APIs. Most trading platforms and broker APIs are tested only at launch. An unpatched API vulnerability can expose your entire client database and is a direct SEBI violation.`, service:'API VAPT + Source Code Audit' }
  ],
  irdai: [
    { urgency:'CRITICAL', trigger:'IS Audit report due within 90 days of FY end', line:`IRDAI mandates IS Audit report submission within 90 days of financial year end or 30 days from audit completion — whichever is earlier. If your FY ended March 2025, your deadline was June 2025. Late submission is a separate IRDAI violation.`, service:'IS Audit (CERT-In Empanelled)' },
    { urgency:'CRITICAL', trigger:'Incident reporting — 6 hours to IRDAI AND CERT-In', line:`IRDAI's March 2025 amendment mandates cyber incident notification to both IRDAI and CERT-In within 6 hours of discovery. Insurance companies must have pre-empanelled forensic experts BEFORE an incident — you cannot start looking for a forensics firm after a breach begins.`, service:'Digital Forensics + IR + Pre-empanelment' },
    { urgency:'HIGH', trigger:'Data localization — ICT logs 180 days', line:`IRDAI mandates all ICT infrastructure logs stored within India for a rolling 180 days. Foreign cloud storage without proper data localization controls violates IRDAI guidelines AND DPDP Act — double liability exposure.`, service:'Data Localization Audit + DPDP Compliance' },
    { urgency:'HIGH', trigger:'CISO mandatory even for intermediaries', line:`IRDAI mandates CISO appointment for all regulated entities — insurers and intermediaries. The CISO leads the IS Team and reports to the CRO. If your organization has no designated CISO, you are in governance non-compliance per IRDAI CS Guidelines 2023.`, service:'Virtual CISO (vCISO)' }
  ],
  general: [
    { urgency:'CRITICAL', trigger:'DPDP Act — ₹250 crore per violation, all industries', line:`DPDP Act 2023 is enacted and applies to EVERY organization processing personal data of Indian citizens — no industry exemption, no size threshold. ₹250 crore maximum penalty per violation. A single data breach without adequate security measures exposes your organization to this liability.`, service:'DPDP Compliance + IS Audit' },
    { urgency:'HIGH', trigger:'CERT-In breach reporting — 6 hours mandatory for all', line:`CERT-In direction (April 2022) mandates ALL Indian organizations to report cyber incidents to CERT-In within 6 hours of noticing. This is not industry-specific — it applies to every company. Non-compliance with CERT-In directions is a criminal violation under IT Act 2000.`, service:'IR + Managed Compliance' },
    { urgency:'HIGH', trigger:'India cyber fraud — ₹2,145 crore cumulative losses', line:`India has lost ₹2,145 crore to cyber fraud across 2.7 million incidents since FY22. 53% increase in ransomware attacks on Indian organizations in 2024. Companies without SOC monitoring average 207 days to detect a breach — industry average with SOC is 21 days.`, service:'C-SOC + VAPT + Phishing Training' }
  ]
};

// ── OBJECTION REBUTTALS ───────────────────────────────────────────────
const REBUTTALS = {
  'We already have a vendor': {
    bank: `Two questions: First, is your current vendor CERT-In empanelled? RBI Section 26 mandates CERT-In empanelment specifically — not just any security vendor. Second, does their scope cover your APIs, mobile banking app, and cloud infrastructure? Most generic vendors miss 2-3 of these. Can you share their CERT-In certificate number?`,
    sebi: `SEBI CSCRF requires CERT-In empanelled vendor for both VAPT and IS Audit. Your current vendor may be competent but may not be on CERT-In's list. Check their empanelment at cert-in.org.in. If they're not listed, your SEBI compliance is currently invalid regardless of their report quality.`,
    irdai: `IRDAI mandates CERT-In empanelled auditor for IS Audit — the audit firm must also meet eligibility criteria in Annexure IV of the CS Guidelines 2023, including minimum experience and team qualifications. Is your current vendor meeting all four annexure criteria?`,
    general: `Understood. Three specific questions: Is your vendor CERT-In empanelled for IS Audit? Do they cover DPDP Act gap assessment specifically? When was your last API security test? Most vendors miss at least one of these, which is where your largest liability sits.`
  },
  'Too expensive': {
    bank: `RBI levied ₹54.78 crore in penalties in FY25. One cooperative bank paid ₹5.93 crore for cybersecurity non-compliance alone. The Banking Regulation Act allows ₹1 crore per day per violation. Our complete compliance package costs a fraction of a single penalty notice. This is not a cost — it is insurance against a known regulatory risk.`,
    sebi: `SEBI can restrict trading operations for non-compliant entities. One day of trading suspension at your volumes would cost more than our annual engagement. CSCRF compliance is cheaper than a SEBI enforcement notice. What is your daily trading volume?`,
    irdai: `IRDAI non-compliance can affect your license. A data breach without adequate controls triggers DPDP Act penalties up to ₹250 crore AND IRDAI enforcement. IBM's 2024 Cost of Data Breach Report puts India's average breach cost at ₹17.9 crore. Our engagement cost is a fraction of either figure.`,
    general: `DPDP Act maximum penalty is ₹250 crore per violation. IBM 2024 puts average Indian breach cost at ₹17.9 crore. CERT-In non-reporting is criminal under IT Act. Our engagement protects you from all three. What is your annual revenue? Our typical engagement is less than 0.3% of that.`
  },
  'Not a priority right now': {
    bank: `RBI IT Directions have been in force since April 2024. Every day of non-compliance is a day of regulatory exposure. The 353 penalties in FY25 were imposed on institutions that also had competing priorities. RBI inspection cycles are not predictable — the question is not whether but when.`,
    sebi: `Every SEBI CSCRF deadline has already passed. You are currently non-compliant, not approaching compliance. SEBI can initiate action any time — the question is whether you want to be compliant before that happens or after. The cost of reactive compliance after enforcement is 3-5x higher.`,
    irdai: `Your IS Audit report for FY25 was due 90 days after March 2025. If not submitted, you are already in violation — this is not a future risk, it is a present one. Additionally, the March 2025 IRDAI amendment added new crisis preparedness requirements that took effect immediately.`,
    general: `CERT-In's 6-hour incident reporting requirement applies today, not from a future date. If you had a breach tomorrow, could your team detect it, contain it, and report it to CERT-In within 6 hours? If not, you face criminal liability under IT Act 2000. That is not a future priority — it is a present gap.`
  },
  'We have ISO 27001': {
    bank: `ISO 27001 is excellent — it satisfies your information security management system requirement. But RBI mandates four additional things beyond ISO: CERT-In VAPT (Section 26), CERT-In IS Audit (Section 30), C-SOC (24/7 monitoring), and documented IRP (Section 27). ISO covers none of these specifically. When was your last Section 26 VAPT done?`,
    sebi: `SEBI CSCRF mandates ISO 27001 AND VAPT AND SOC AND Red Teaming AND IS Audit AND CISO AND API security. ISO 27001 satisfies one of seven requirements. You have the certification — you still need the remaining six. Which of these are in progress?`,
    irdai: `ISO 27001 is a strong foundation, but IRDAI CS Guidelines 2023 mandate specific additional requirements: CERT-In IS Audit with Annexure III format submission to IRDAI, 24x7 SOC with 180-day log retention, pre-empanelled forensic experts, and the new 6-hour incident notification per March 2025 amendment. ISO does not cover any of these.`,
    general: `ISO 27001 covers your ISMS framework — it is the right starting point. But DPDP Act requires specific technical security measures for personal data protection that may not be in your current ISO scope. Additionally, CERT-In's breach reporting requirements and VAPT obligations are separate from ISO. A gap assessment would show exactly what ISO covers and what it does not.`
  },
  'We do it internally': {
    bank: `RBI Section 30 is explicit — IS Audit must be by a CERT-In EMPANELLED EXTERNAL organization. Internal teams cannot conduct this audit. Additionally, Section 26 VAPT should be by an external CERT-In vendor. X10 Financial had its CoR cancelled specifically for conducting risk functions internally without external oversight. Self-audit creates the exact conflict of interest that regulators penalize.`,
    sebi: `SEBI CSCRF requires external CERT-In empanelled organization for IS Audit. The auditor's checklist must be submitted to your exchange — internal reports do not satisfy this requirement. The regulator specifically requires independence because internal teams have inherent conflicts of interest when auditing their own systems.`,
    irdai: `IRDAI mandates annual IS Audit by an independent external auditor meeting specific eligibility criteria in Annexure IV. Internal team audits are explicitly insufficient. The audit report must be signed by the external auditor and submitted to IRDAI — your internal team cannot sign this certificate.`,
    general: `Internal security reviews are valuable for continuous monitoring but do not satisfy regulatory compliance requirements. CERT-In VAPT and IS Audit require external empanelled vendors. DPDP Act's security requirements need independent verification. Internal reviews have a 40% average miss rate on critical vulnerabilities versus external assessments — the conflict of interest is structural.`
  }
};

// ── PROMPT BUILDERS ───────────────────────────────────────────────────
function buildRegulatoryContext(industry, mode) {
  const ind = (industry||'').toLowerCase();
  const isBank   = /bank|nbfc|cooperative|ucb|payment bank|credit|microfinance|rbi/.test(ind) || mode==='bank';
  const isSebi   = /broker|exchange|mutual fund|amc|depository|portfolio|rta|clearing|investment advisor|sebi/.test(ind);
  const isIrdai  = /insurance|insurer|tpa|irdai|reinsur/.test(ind);
  const isFintech= /fintech|payment aggregator|wallet|prepaid|upi|payment gateway/.test(ind);

  // NOT a financial entity → return empty string. RBI data must NEVER appear for pharma/IT/manufacturing.
  if (!isBank && !isSebi && !isIrdai && !isFintech) return '';

  const showAll  = !isBank && !isSebi && !isIrdai;

  const L = ['\n=== REGULATORY INTELLIGENCE (cite exact refs in scripts) ===\n'];

  // Always show enforcement reality
  L.push(`RBI ENFORCEMENT FY2024-25 (use these numbers in every script):
• ${RBI_ENFORCEMENT.fy2025.penalties} penalties, ${RBI_ENFORCEMENT.fy2025.total} total — cybersecurity was TOP violation
• Cooperative bank: ${RBI_ENFORCEMENT.notable[0].amount} for ${RBI_ENFORCEMENT.notable[0].reason}
• X10 Financial: CoR CANCELLED for outsourcing without due diligence (Jan 2025)
• UPI fraud: ${RBI_ENFORCEMENT.upi_fraud.fy25_loss} lost in FY25 (${RBI_ENFORCEMENT.upi_fraud.fy25_incidents} incidents)
• Source: ${RBI_ENFORCEMENT.source}\n`);

  if (isBank || isFintech) {
    L.push('RBI IT DIRECTIONS 2023 — KEY MANDATES (cite section in every script):');
    RBI_IT_DIRECTIONS_2023.mandates.forEach(m => {
      L.push(`  [${m.sec}] ${m.title}: ${m.req}`);
      L.push(`    Gap indicator: ${m.gap} | Service: ${m.service} | Penalty: ${m.penalty}`);
    });
    L.push(`\n  Effective: ${RBI_IT_DIRECTIONS_2023.effective} | Ref: ${RBI_IT_DIRECTIONS_2023.ref}`);
    if (isFintech) {
      L.push('\nRBI PSO CYBER RESILIENCE 2024:');
      RBI_PSO_2024.mandates.forEach(m => L.push(`  ${m.title}: ${m.req} | Penalty: ${m.penalty}`));
    }
    L.push('\nBANK TRIGGERS — use these verbatim in scripts:');
    TRIGGERS.bank.forEach(t => L.push(`  [${t.urgency}] "${t.line}" → Service: ${t.service}`));
  }

  if (isSebi) {
    L.push('\nSEBI CSCRF 2024 — ALL DEADLINES PAST DUE:');
    Object.entries(SEBI_CSCRF.entity_categories).forEach(([cat,data]) => {
      L.push(`  [${cat}] Deadline: ${data.deadline} | Requirements: ${data.requirements.join(', ')}`);
    });
    L.push('\nSEBI MANDATES (cite CSCRF reference in scripts):');
    SEBI_CSCRF.mandates.forEach(m => L.push(`  [${m.ref}] ${m.title}: ${m.req} | Gap: ${m.gap} | Service: ${m.service}`));
    L.push('\nSEBI TRIGGERS:');
    TRIGGERS.sebi.forEach(t => L.push(`  [${t.urgency}] "${t.line}" → ${t.service}`));
  }

  if (isIrdai) {
    L.push('\nIRDAI CS GUIDELINES 2023 (amended March 2025):');
    IRDAI_GUIDELINES.mandates.forEach(m => L.push(`  ${m.title}: ${m.req} | Gap: ${m.gap} | Penalty: ${m.penalty}`));
    L.push('\nIRDAI TRIGGERS:');
    TRIGGERS.irdai.forEach(t => L.push(`  [${t.urgency}] "${t.line}" → ${t.service}`));
  }

  L.push('\nDPDP ACT 2023 (applies to ALL industries):');
  L.push(`  Status: ${DPDP_ACT.status}`);
  DPDP_ACT.key_obligations.forEach(o => L.push(`  [${o.sec}] ${o.title}: ${o.req}`));
  L.push(`  Max penalty: ${DPDP_ACT.penalties.data_breach}`);

  if (showAll) {
    L.push('\nGENERAL TRIGGERS:');
    TRIGGERS.general.forEach(t => L.push(`  [${t.urgency}] "${t.line}" → ${t.service}`));
  }

  L.push('\n=== END REGULATORY INTELLIGENCE ===\n');
  return L.join('\n');
}

function buildObjectionContext(industry) {
  const ind = (industry||'').toLowerCase();
  const isBank  = /bank|nbfc|cooperative|ucb|payment|rbi/.test(ind);
  const isSebi  = /broker|exchange|fund|depository|portfolio|sebi/.test(ind);
  const isIrdai = /insurance|tpa|irdai/.test(ind);
  const key     = isBank ? 'bank' : isSebi ? 'sebi' : isIrdai ? 'irdai' : 'general';

  const L = ['\n=== OBJECTION REBUTTALS (use exact wording — cite regulations) ===\n'];
  Object.entries(REBUTTALS).forEach(([obj, resp]) => {
    L.push(`OBJECTION: "${obj}"`);
    L.push(`REBUTTAL: ${resp[key] || resp.general}`);
    L.push('');
  });
  L.push('=== END OBJECTION REBUTTALS ===\n');
  return L.join('\n');
}

const DEEP_INTELLIGENCE_PROMPT = `Extract from website, LinkedIn, news:
SCALE: Revenue, employees, branches, clients, AUM
TECH: Core systems, cloud providers, mobile apps (name them), APIs, tech stack from job postings  
CYBER POSTURE: Any breach history, RBI/SEBI/IRDAI penalties received, certifications visible, CISO named, security job postings
REGULATORY: Exact regulator, license type, enforcement actions last 3 years
LEADERSHIP: CEO, CTO, CISO (name and LinkedIn if visible), CFO
RECENT (12 months): Funding, M&A, new products, leadership changes, incidents`;

module.exports = { buildRegulatoryContext, buildObjectionContext, DEEP_INTELLIGENCE_PROMPT, RBI_ENFORCEMENT, TRIGGERS, REBUTTALS };
