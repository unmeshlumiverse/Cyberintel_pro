-- ════════════════════════════════════════════════════════════════════════
-- CyberIntel Pro — Admin Operations Reference
-- Run specific sections as needed
-- ════════════════════════════════════════════════════════════════════════

\c cyberintel_pro;

-- ════════════════════════════════════════════════════════════════════════
-- ① CREATE A NEW USER (Admin creates with temp password)
-- ════════════════════════════════════════════════════════════════════════
-- Replace the values below then run
INSERT INTO users (email, password_hash, salt, name, company_name, phone, role, status, must_change_pwd)
VALUES (
  'newuser@example.com',                              -- ← email
  crypt('TempPass@123', gen_salt('bf', 10)),           -- ← temp password
  gen_salt('bf', 10),
  'Full Name',                                        -- ← name
  'Their Company Pvt. Ltd.',                          -- ← company
  '+91-XXXXXXXXXX',                                   -- ← phone (optional)
  'user',                                             -- ← role: 'user' | 'admin' | 'superadmin'
  'active',
  TRUE                                                -- ← force password change on first login
);

-- ════════════════════════════════════════════════════════════════════════
-- ② MAKE SOMEONE SUPERADMIN
-- ════════════════════════════════════════════════════════════════════════
UPDATE users
SET role = 'superadmin', updated_at = NOW()
WHERE email = 'target@example.com';    -- ← replace email

-- ════════════════════════════════════════════════════════════════════════
-- ③ MAKE SOMEONE ADMIN
-- ════════════════════════════════════════════════════════════════════════
UPDATE users
SET role = 'admin', updated_at = NOW()
WHERE email = 'target@example.com';

-- ════════════════════════════════════════════════════════════════════════
-- ④ RESET A USER'S PASSWORD (Admin sets temp password)
-- ════════════════════════════════════════════════════════════════════════
UPDATE users
SET
  password_hash   = crypt('NewTemp@456', gen_salt('bf', 10)),
  salt            = gen_salt('bf', 10),
  must_change_pwd = TRUE,
  updated_at      = NOW()
WHERE email = 'target@example.com';

-- ════════════════════════════════════════════════════════════════════════
-- ⑤ USER CHANGES OWN PASSWORD (called from app)
-- ════════════════════════════════════════════════════════════════════════
UPDATE users
SET
  password_hash   = crypt('MyNewPassword@789', gen_salt('bf', 10)),
  salt            = gen_salt('bf', 10),
  must_change_pwd = FALSE,
  updated_at      = NOW()
WHERE id = '<<user-uuid-here>>';

-- ════════════════════════════════════════════════════════════════════════
-- ⑥ SUSPEND / REACTIVATE USER
-- ════════════════════════════════════════════════════════════════════════
UPDATE users SET status = 'suspended', updated_at = NOW() WHERE email = 'target@example.com';
UPDATE users SET status = 'active',    updated_at = NOW() WHERE email = 'target@example.com';

-- ════════════════════════════════════════════════════════════════════════
-- ⑦ VIEW ALL USERS
-- ════════════════════════════════════════════════════════════════════════
SELECT
  email, name, company_name, role, status,
  must_change_pwd, last_login, login_count,
  created_at
FROM users
ORDER BY role DESC, created_at;

-- ════════════════════════════════════════════════════════════════════════
-- ⑧ VIEW USER ACTIVITY DASHBOARD
-- ════════════════════════════════════════════════════════════════════════
SELECT
  email, name, role, status,
  total_searches, total_reports, avg_risk_score,
  last_search_at, last_login
FROM v_user_activity
ORDER BY total_searches DESC;

-- ════════════════════════════════════════════════════════════════════════
-- ⑨ VIEW RECENT SEARCHES (last 50)
-- ════════════════════════════════════════════════════════════════════════
SELECT
  s.created_at,
  s.company_name,
  s.domain,
  s.risk_score,
  s.risk_level,
  s.gap_count,
  s.cve_count,
  s.spf_ok,
  s.dmarc_ok,
  s.mode,
  s.user_email,
  s.user_name
FROM v_recent_searches s
LIMIT 50;

-- ════════════════════════════════════════════════════════════════════════
-- ⑩ VIEW REPORTS SENT (last 50)
-- ════════════════════════════════════════════════════════════════════════
SELECT
  r.created_at,
  r.company_name,
  r.sent_to,
  r.sent_from,
  r.subject,
  r.delivery_method,
  r.delivery_status,
  r.risk_score,
  r.gap_count,
  r.user_email
FROM v_reports_full r
LIMIT 50;

-- ════════════════════════════════════════════════════════════════════════
-- ⑪ SEARCH HISTORY FOR SPECIFIC USER
-- ════════════════════════════════════════════════════════════════════════
SELECT
  s.created_at,
  s.company_name,
  s.domain,
  s.risk_score,
  s.gap_count,
  s.mode
FROM searches s
JOIN users u ON u.id = s.user_id
WHERE u.email = 'target@example.com'
ORDER BY s.created_at DESC;

-- ════════════════════════════════════════════════════════════════════════
-- ⑫ AUDIT LOG — view all sensitive actions
-- ════════════════════════════════════════════════════════════════════════
SELECT
  al.created_at,
  u.email AS actor,
  al.action,
  al.target_type,
  al.details,
  al.ip_address
FROM audit_log al
LEFT JOIN users u ON u.id = al.user_id
ORDER BY al.created_at DESC
LIMIT 100;

-- ════════════════════════════════════════════════════════════════════════
-- ⑬ DELETE USER (soft delete — suspend instead is preferred)
-- ════════════════════════════════════════════════════════════════════════
-- WARNING: this deletes all searches and reports for this user too
-- DELETE FROM users WHERE email = 'target@example.com';

-- ════════════════════════════════════════════════════════════════════════
-- ⑭ STATS OVERVIEW
-- ════════════════════════════════════════════════════════════════════════
SELECT
  (SELECT COUNT(*) FROM users WHERE status='active')          AS active_users,
  (SELECT COUNT(*) FROM users WHERE role='superadmin')        AS superadmins,
  (SELECT COUNT(*) FROM users WHERE role='admin')             AS admins,
  (SELECT COUNT(*) FROM searches)                             AS total_searches,
  (SELECT COUNT(*) FROM reports)                              AS total_reports,
  (SELECT ROUND(AVG(risk_score)) FROM searches)               AS avg_risk_score,
  (SELECT COUNT(*) FROM searches WHERE risk_level='CRITICAL') AS critical_scans;

