-- ════════════════════════════════════════════════════════════════════════
-- CyberIntel Pro — PostgreSQL Database Setup
-- Lumiverse Solutions Pvt. Ltd.
-- Run as: psql -U postgres -f database_setup.sql
-- ════════════════════════════════════════════════════════════════════════

-- ── CREATE DATABASE ───────────────────────────────────────────────────
CREATE DATABASE cyberintel_pro
  WITH ENCODING = 'UTF8'
       LC_COLLATE = 'en_US.UTF-8'
       LC_CTYPE = 'en_US.UTF-8'
       TEMPLATE = template0;

\c cyberintel_pro;

-- ── EXTENSIONS ───────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ════════════════════════════════════════════════════════════════════════
-- TABLE: users
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email           VARCHAR(255) UNIQUE NOT NULL,
  password_hash   TEXT NOT NULL,
  salt            VARCHAR(64) NOT NULL,
  name            VARCHAR(255),
  company_name    VARCHAR(255),
  phone           VARCHAR(30),
  role            VARCHAR(20) NOT NULL DEFAULT 'user'
                    CHECK (role IN ('superadmin', 'admin', 'user')),
  status          VARCHAR(20) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended', 'pending')),
  must_change_pwd BOOLEAN NOT NULL DEFAULT TRUE,  -- force password change on first login
  created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login      TIMESTAMPTZ,
  login_count     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_users_email  ON users(email);
CREATE INDEX idx_users_role   ON users(role);
CREATE INDEX idx_users_status ON users(status);

-- ════════════════════════════════════════════════════════════════════════
-- TABLE: user_sessions
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE user_sessions (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,  -- store hash of JWT, not raw token
  ip_address  INET,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
  revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_token   ON user_sessions(token_hash);

-- ════════════════════════════════════════════════════════════════════════
-- TABLE: searches
-- Full record of every company scan performed by every user
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE searches (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Target company info
  company_name    VARCHAR(500),
  website         VARCHAR(500) NOT NULL,
  domain          VARCHAR(255),
  industry        VARCHAR(100),
  headquarters    VARCHAR(255),
  employee_range  VARCHAR(50),
  mode            VARCHAR(20) DEFAULT 'corporate'
                    CHECK (mode IN ('corporate', 'bank', 'cp')),

  -- Risk assessment
  risk_score      INTEGER CHECK (risk_score BETWEEN 0 AND 100),
  risk_level      VARCHAR(20) CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  gap_count       INTEGER DEFAULT 0,
  critical_gaps   INTEGER DEFAULT 0,

  -- Security findings (key fields from scan)
  ip_address      INET,
  spf_ok          BOOLEAN,
  dmarc_ok        BOOLEAN,
  dmarc_policy    VARCHAR(20),
  ssl_days        INTEGER,
  blacklisted     BOOLEAN DEFAULT FALSE,
  cve_count       INTEGER DEFAULT 0,
  cves            TEXT[],             -- array of CVE IDs e.g. ['CVE-2024-1234']
  open_ports      INTEGER[],
  abuse_score     INTEGER,
  hibp_breached   BOOLEAN DEFAULT FALSE,
  hibp_count      INTEGER DEFAULT 0,
  hudson_count    INTEGER DEFAULT 0,  -- infostealer records
  vt_malicious    INTEGER DEFAULT 0,

  -- Full scan + analysis JSON blobs
  scan_data       JSONB,    -- full raw scan object
  analysis_data   JSONB,    -- full Gemini analysis result
  gaps_data       JSONB,    -- compliance gaps array
  intel_data      JSONB,    -- intel findings

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_searches_user_id      ON searches(user_id);
CREATE INDEX idx_searches_domain       ON searches(domain);
CREATE INDEX idx_searches_company_name ON searches(company_name);
CREATE INDEX idx_searches_created_at   ON searches(created_at DESC);
CREATE INDEX idx_searches_risk_score   ON searches(risk_score DESC);
CREATE INDEX idx_searches_scan_data    ON searches USING GIN(scan_data);
CREATE INDEX idx_searches_analysis     ON searches USING GIN(analysis_data);

-- ════════════════════════════════════════════════════════════════════════
-- TABLE: reports
-- Every report sent (email, PDF download, copy)
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE reports (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  search_id       UUID REFERENCES searches(id) ON DELETE SET NULL,

  -- Target info
  company_name    VARCHAR(500),
  domain          VARCHAR(255),

  -- Delivery info
  sent_to         VARCHAR(255),     -- recipient email
  sent_from       VARCHAR(255),     -- sender (logged-in user) email
  subject         VARCHAR(500),
  delivery_method VARCHAR(20) DEFAULT 'email'
                    CHECK (delivery_method IN ('email','gmail','pdf_download','copy','mailto')),
  delivery_status VARCHAR(20) DEFAULT 'sent'
                    CHECK (delivery_status IN ('sent','failed','pending','opened')),
  personal_note   TEXT,

  -- Report content snapshot
  risk_score      INTEGER,
  gap_count       INTEGER,
  report_html     TEXT,   -- full HTML report for audit trail

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_user_id    ON reports(user_id);
CREATE INDEX idx_reports_search_id  ON reports(search_id);
CREATE INDEX idx_reports_sent_to    ON reports(sent_to);
CREATE INDEX idx_reports_created_at ON reports(created_at DESC);

-- ════════════════════════════════════════════════════════════════════════
-- TABLE: email_finder_results
-- Decision maker / email discovery results
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE email_finder_results (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  search_id       UUID REFERENCES searches(id) ON DELETE SET NULL,
  domain          VARCHAR(255) NOT NULL,
  company_name    VARCHAR(500),
  role_searched   VARCHAR(255),

  -- Results
  emails_checked  INTEGER DEFAULT 0,
  emails_verified INTEGER DEFAULT 0,
  email_pattern   VARCHAR(255),
  contacts        JSONB,    -- [{email, name, role, confidence, source, valid}]

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_finder_user_id ON email_finder_results(user_id);
CREATE INDEX idx_email_finder_domain  ON email_finder_results(domain);

-- ════════════════════════════════════════════════════════════════════════
-- TABLE: notes
-- Per-company notes by user
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE notes (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain       VARCHAR(255),
  company_name VARCHAR(500),
  note         TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notes_user_id ON notes(user_id);
CREATE INDEX idx_notes_domain  ON notes(domain);

-- ════════════════════════════════════════════════════════════════════════
-- TABLE: audit_log
-- All sensitive actions logged for compliance
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE audit_log (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  action      VARCHAR(100) NOT NULL,   -- 'login','logout','user_create','role_change','password_reset'
  target_id   UUID,                    -- affected user/search/report ID
  target_type VARCHAR(50),             -- 'user','search','report'
  details     JSONB,
  ip_address  INET,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user_id    ON audit_log(user_id);
CREATE INDEX idx_audit_created_at ON audit_log(created_at DESC);
CREATE INDEX idx_audit_action     ON audit_log(action);

-- ════════════════════════════════════════════════════════════════════════
-- FUNCTIONS & TRIGGERS
-- ════════════════════════════════════════════════════════════════════════

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_notes_updated_at
  BEFORE UPDATE ON notes
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ════════════════════════════════════════════════════════════════════════
-- VIEWS
-- ════════════════════════════════════════════════════════════════════════

-- User activity dashboard view
CREATE VIEW v_user_activity AS
SELECT
  u.id,
  u.email,
  u.name,
  u.company_name,
  u.role,
  u.status,
  u.last_login,
  u.login_count,
  u.created_at,
  COUNT(DISTINCT s.id) AS total_searches,
  COUNT(DISTINCT r.id) AS total_reports,
  MAX(s.created_at)    AS last_search_at,
  ROUND(AVG(s.risk_score))::INTEGER AS avg_risk_score
FROM users u
LEFT JOIN searches s ON s.user_id = u.id
LEFT JOIN reports  r ON r.user_id = u.id
GROUP BY u.id, u.email, u.name, u.company_name, u.role, u.status,
         u.last_login, u.login_count, u.created_at;

-- Recent searches with user info
CREATE VIEW v_recent_searches AS
SELECT
  s.*,
  u.email        AS user_email,
  u.name         AS user_name,
  u.company_name AS user_company
FROM searches s
JOIN users u ON u.id = s.user_id
ORDER BY s.created_at DESC;

-- Reports with full context
CREATE VIEW v_reports_full AS
SELECT
  r.*,
  u.email        AS user_email,
  u.name         AS user_name,
  s.domain       AS search_domain,
  s.risk_score   AS search_risk_score
FROM reports r
JOIN users   u ON u.id = r.user_id
LEFT JOIN searches s ON s.id = r.search_id
ORDER BY r.created_at DESC;

-- ════════════════════════════════════════════════════════════════════════
-- SEED: INSERT SUPERADMIN — ba@lumiversesolutions.com
-- Password: Lumiverse@2026  (CHANGE THIS IMMEDIATELY after first login)
-- ════════════════════════════════════════════════════════════════════════

-- Generate salt and hash for initial password
-- Using pgcrypto crypt() with bcrypt (10 rounds)
INSERT INTO users (
  id, email, password_hash, salt, name, company_name, role, status, must_change_pwd, created_at
) VALUES (
  uuid_generate_v4(),
  'ba@lumiversesolutions.com',
  -- bcrypt hash of 'Lumiverse@2026' — change via admin panel immediately
  crypt('Lumiverse@2026', gen_salt('bf', 10)),
  gen_salt('bf', 10),
  'Lumiverse Admin',
  'Lumiverse Solutions Pvt. Ltd.',
  'superadmin',
  'active',
  FALSE,  -- superadmin can skip forced password change
  NOW()
) ON CONFLICT (email) DO UPDATE SET
  role = 'superadmin',
  status = 'active';

