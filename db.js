// ════════════════════════════════════════════════════════════════════════
// CyberIntel Pro — PostgreSQL Database Module
// Lumiverse Solutions Pvt. Ltd.
// ════════════════════════════════════════════════════════════════════════
// Install: npm install pg
// Usage in server.js: const db = require('./db');

const { Pool } = require('pg');
const crypto   = require('crypto');
const path     = require('path');
const fs       = require('fs');

// ── Connection Pool ───────────────────────────────────────────────────
const pool = new Pool({
  host:     process.env.PGHOST     || 'localhost',
  port:     parseInt(process.env.PGPORT || '5432'),
  database: process.env.PGDATABASE || 'cyberintel_pro',
  user:     process.env.PGUSER     || 'postgres',
  password: process.env.PGPASSWORD || 'your_postgres_password',
  max:      10,           // max pool connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  console.error('[DB] Pool error:', err.message);
});

// ── Test connection ───────────────────────────────────────────────────
async function testConnection() {
  try {
    const client = await pool.connect();
    const res = await client.query('SELECT NOW() AS now, current_database() AS db');
    client.release();
    console.log('[DB] Connected to PostgreSQL:', res.rows[0].db, 'at', res.rows[0].now);
    return true;
  } catch(e) {
    console.error('[DB] Connection FAILED:', e.message);
    console.error('[DB] Check PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD env vars');
    return false;
  }
}

// ── Password hashing (HMAC-SHA256 + scrypt) ──────────────────────────
// Note: We use Node crypto for compatibility with existing users.json hashes
// New PostgreSQL users will be hashed with scrypt
function hashPassword(password, salt) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(key.toString('hex')))
  );
}
function makeToken(payload, secret) {
  const JWT_SECRET = secret || process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable is required");
}
  const h = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const b = Buffer.from(JSON.stringify({...payload, iat:Date.now(), exp:Date.now()+30*24*60*60*1000})).toString('base64url');
  const s = crypto.createHmac('sha256', JWT_SECRET).update(h+'.'+b).digest('base64url');
  return `${h}.${b}.${s}`;
}
function verifyToken(token) {
  const JWT_SECRET = secret || process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is missing");
}

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is missing");
}
  try {
    const [h,b,s] = (token||'').split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(h+'.'+b).digest('base64url');
    if (s !== expected) return null;
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ════════════════════════════════════════════════════════════════════════
// USER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════

const Users = {

  // Find user by email
  async findByEmail(email) {
    const res = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND status != $2',
      [email.toLowerCase().trim(), 'deleted']
    );
    return res.rows[0] || null;
  },

  // Find user by ID
  async findById(id) {
    const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return res.rows[0] || null;
  },

  // List all users (admin view)
  async listAll({ role, status, limit = 100 } = {}) {
    let q = 'SELECT id,email,name,company_name,phone,role,status,must_change_pwd,last_login,login_count,created_at FROM users WHERE 1=1';
    const params = [];
    if (role)   { params.push(role);   q += ` AND role = $${params.length}`; }
    if (status) { params.push(status); q += ` AND status = $${params.length}`; }
    params.push(limit);
    q += ` ORDER BY created_at DESC LIMIT $${params.length}`;
    const res = await pool.query(q, params);
    return res.rows;
  },

  // Create user (admin creates with temp password)
  async create({ email, password, name, company_name, phone, role = 'user', created_by = null }) {
    const key   = email.toLowerCase().trim();
    const salt  = crypto.randomBytes(16).toString('hex');
    const hash  = await hashPassword(password, salt);
    const res   = await pool.query(
      `INSERT INTO users (email, password_hash, salt, name, company_name, phone, role, created_by, must_change_pwd)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE)
       RETURNING id, email, name, company_name, role, status, must_change_pwd`,
      [key, hash, salt, name||null, company_name||null, phone||null, role, created_by||null]
    );
    return res.rows[0];
  },

  // Signup (self-registration)
  async signup({ email, password, name, company_name }) {
    const key = email.toLowerCase().trim();
    // Check if already exists
    const existing = await pool.query('SELECT id FROM users WHERE email=$1', [key]);
    if (existing.rows.length) throw new Error('Account already exists. Please sign in.');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await hashPassword(password, salt);
    const res  = await pool.query(
      `INSERT INTO users (email, password_hash, salt, name, company_name, role, must_change_pwd)
       VALUES ($1,$2,$3,$4,$5,'user',FALSE)
       RETURNING id, email, name, company_name, role, must_change_pwd`,
      [key, hash, salt, name||null, company_name||null]
    );
    const user  = res.rows[0];
    const token = makeToken({ id: user.id, email: user.email, role: user.role });
    await pool.query('UPDATE users SET last_login=NOW(), login_count=login_count+1 WHERE id=$1', [user.id]);
    return { token, user };
  },

  // Login
  async login({ email, password }) {
    const key  = email.toLowerCase().trim();
    const user = await Users.findByEmail(key);
    if (!user) {
      // Check if any users exist at all
      const count = await pool.query('SELECT COUNT(*) FROM users');
      const total = parseInt(count.rows[0].count);
      console.log('[Auth] User not found:', key, '| Total users in DB:', total);
      if (total === 0) throw Object.assign(new Error('No accounts exist yet. Run: node seed_admin.js'), { code: 404 });
      throw Object.assign(new Error('Account not found. Check email or ask admin to create account.'), { code: 404 });
    }
    if (user.status === 'suspended') throw Object.assign(new Error('Account suspended. Contact admin.'), { code: 403 });

    console.log('[Auth] Verifying password for:', key, '| hash_len:', user.password_hash?.length, '| salt_len:', user.salt?.length);
    const hash = await hashPassword(password, user.salt);
    if (hash !== user.password_hash) {
      console.log('[Auth] Password mismatch for:', key);
      throw Object.assign(new Error('Incorrect password.'), { code: 401 });
    }

    // Update login stats
    await pool.query('UPDATE users SET last_login=NOW(), login_count=login_count+1 WHERE id=$1', [user.id]);
    const token = makeToken({ id: user.id, email: user.email, role: user.role });

    console.log('[Auth] Login success:', user.email, '| role:', user.role);
    return {
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role, must_change_pwd: user.must_change_pwd }
    };
  },

  // Change own password
  async changePassword({ user_id, current_password, new_password }) {
    const user = await Users.findById(user_id);
    if (!user) throw new Error('User not found');
    const hash = await hashPassword(current_password, user.salt);
    if (hash !== user.password_hash) throw new Error('Current password is incorrect');
    if (new_password.length < 8) throw new Error('New password must be at least 8 characters');
    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = await hashPassword(new_password, newSalt);
    await pool.query(
      'UPDATE users SET password_hash=$1, salt=$2, must_change_pwd=FALSE, updated_at=NOW() WHERE id=$3',
      [newHash, newSalt, user_id]
    );
    return { ok: true };
  },

  // Admin: reset any user's password
  async adminResetPassword({ target_email, new_password, admin_id }) {
    const salt  = crypto.randomBytes(16).toString('hex');
    const hash  = await hashPassword(new_password, salt);
    const res   = await pool.query(
      'UPDATE users SET password_hash=$1, salt=$2, must_change_pwd=TRUE, updated_at=NOW() WHERE email=$3 RETURNING id,email',
      [hash, salt, target_email.toLowerCase().trim()]
    );
    if (!res.rows.length) throw new Error('User not found');
    await AuditLog.log({ user_id: admin_id, action: 'admin_password_reset', target_id: res.rows[0].id, target_type: 'user', details: { email: target_email } });
    return { ok: true, email: res.rows[0].email };
  },

  // Admin: change role
  async setRole({ target_email, role, admin_id }) {
    if (!['user','admin','superadmin'].includes(role)) throw new Error('Invalid role');
    const res = await pool.query(
      'UPDATE users SET role=$1, updated_at=NOW() WHERE email=$2 RETURNING id,email,role',
      [role, target_email.toLowerCase().trim()]
    );
    if (!res.rows.length) throw new Error('User not found');
    await AuditLog.log({ user_id: admin_id, action: 'role_change', target_id: res.rows[0].id, target_type: 'user', details: { email: target_email, new_role: role } });
    return res.rows[0];
  },

  // Admin: suspend/activate
  async setStatus({ target_email, status, admin_id }) {
    if (!['active','suspended'].includes(status)) throw new Error('Invalid status');
    const res = await pool.query(
      'UPDATE users SET status=$1, updated_at=NOW() WHERE email=$2 RETURNING id,email',
      [status, target_email.toLowerCase().trim()]
    );
    if (!res.rows.length) throw new Error('User not found');
    await AuditLog.log({ user_id: admin_id, action: 'status_change', target_id: res.rows[0].id, target_type: 'user', details: { email: target_email, new_status: status } });
    return { ok: true };
  },

  // Verify JWT token
  async verifyToken(token) {
    const payload = verifyToken(token);
    if (!payload) throw Object.assign(new Error('Invalid or expired session'), { code: 401 });
    const user = await Users.findById(payload.id);
    if (!user || user.status !== 'active') throw Object.assign(new Error('Account not found or suspended'), { code: 401 });
    return { id: user.id, email: user.email, role: user.role, name: user.name, must_change_pwd: user.must_change_pwd };
  },

  // Get activity summary (admin view)
  async getActivitySummary() {
    const res = await pool.query('SELECT * FROM v_user_activity ORDER BY total_searches DESC LIMIT 50');
    return res.rows;
  },
};

// ════════════════════════════════════════════════════════════════════════
// SEARCHES
// ════════════════════════════════════════════════════════════════════════

const Searches = {

  // Save a completed scan
  async save({ user_id, result, scan, industry }) {
    const riskLevel = (score) =>
      score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
    const domain = scan?.domain || result?.website || '';
    const res = await pool.query(
      `INSERT INTO searches (
        user_id, company_name, website, domain, industry, headquarters, employee_range, mode,
        risk_score, risk_level, gap_count, critical_gaps,
        ip_address, spf_ok, dmarc_ok, dmarc_policy, ssl_days, blacklisted,
        cve_count, cves, open_ports, abuse_score, hibp_breached, hibp_count,
        hudson_count, vt_malicious, scan_data, analysis_data, gaps_data
       ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,
        $9,$10,$11,$12,
        $13,$14,$15,$16,$17,$18,
        $19,$20,$21,$22,$23,$24,
        $25,$26,$27,$28,$29
       ) RETURNING id`,
      [
        user_id,
        result?.company_name || null,
        result?.website || domain,
        domain,
        industry || result?.industry || null,
        result?.headquarters || null,
        result?.employee_range || null,
        result?.mode || 'corporate',
        result?.risk_score || null,
        riskLevel(result?.risk_score || 50),
        (result?.compliance_gaps || []).length,
        (result?.compliance_gaps || []).filter(g => g.impact_level === 'critical').length,
        scan?.ip || null,
        scan?.dns?.spf?.exists || false,
        scan?.dns?.dmarc?.exists || false,
        scan?.dns?.dmarc?.policy || null,
        scan?.dns?.ssl?.days_left || null,
        scan?.dns?.blacklist?.listed || false,
        (scan?.shodan?.vulns || []).length,
        scan?.shodan?.vulns || [],
        scan?.shodan?.ports || [],
        scan?.abuse_ipdb?.abuse_score || null,
        scan?.hibp?.breached || false,
        scan?.hibp?.count || 0,
        scan?.hudson_rock?.stealers_count || 0,
        scan?.virustotal?.malicious || 0,
        scan ? JSON.stringify(scan) : null,
        result ? JSON.stringify(result) : null,
        result?.compliance_gaps ? JSON.stringify(result.compliance_gaps) : null,
      ]
    );
    return res.rows[0].id;
  },

  // Get user's search history
  async getByUser(user_id, { limit = 20 } = {}) {
    const res = await pool.query(
      `SELECT id, company_name, website, domain, industry, risk_score, risk_level,
              gap_count, cve_count, spf_ok, dmarc_ok, mode, created_at
       FROM searches WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`,
      [user_id, limit]
    );
    return res.rows;
  },

  // Admin: all searches
  async getAll({ limit = 100, user_id } = {}) {
    const params = [limit];
    let q = 'SELECT * FROM v_recent_searches ';
    if (user_id) { params.unshift(user_id); q += 'WHERE user_id=$1 '; params[params.length-1] = limit; }
    q += `LIMIT $${params.length}`;
    const res = await pool.query(q, params);
    return res.rows;
  },

  // Admin: search by company name or domain
  async search(query) {
    const res = await pool.query(
      `SELECT id,company_name,domain,risk_score,gap_count,user_email,user_name,created_at
       FROM v_recent_searches
       WHERE company_name ILIKE $1 OR domain ILIKE $1
       LIMIT 50`,
      [`%${query}%`]
    );
    return res.rows;
  },
};

// ════════════════════════════════════════════════════════════════════════
// REPORTS
// ════════════════════════════════════════════════════════════════════════

const Reports = {

  async save({ user_id, search_id, company_name, domain, sent_to, sent_from, subject, delivery_method, personal_note, risk_score, gap_count, report_html }) {
    const res = await pool.query(
      `INSERT INTO reports (user_id,search_id,company_name,domain,sent_to,sent_from,subject,delivery_method,personal_note,risk_score,gap_count,report_html)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
      [user_id, search_id||null, company_name||null, domain||null, sent_to||null, sent_from||null, subject||null,
       delivery_method||'email', personal_note||null, risk_score||null, gap_count||null, report_html||null]
    );
    return res.rows[0].id;
  },

  async getByUser(user_id, { limit = 20 } = {}) {
    const res = await pool.query(
      `SELECT id,company_name,domain,sent_to,sent_from,subject,delivery_method,risk_score,gap_count,created_at
       FROM reports WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`,
      [user_id, limit]
    );
    return res.rows;
  },

  async getAll({ limit = 100 } = {}) {
    const res = await pool.query(`SELECT * FROM v_reports_full LIMIT $1`, [limit]);
    return res.rows;
  },
};

// ════════════════════════════════════════════════════════════════════════
// NOTES
// ════════════════════════════════════════════════════════════════════════

const Notes = {
  async save({ user_id, domain, company_name, note }) {
    await pool.query(
      `INSERT INTO notes (user_id,domain,company_name,note) VALUES ($1,$2,$3,$4)
       ON CONFLICT DO NOTHING`,
      [user_id, domain||null, company_name||null, note]
    );
  },
  async getByUser(user_id) {
    const res = await pool.query(
      'SELECT * FROM notes WHERE user_id=$1 ORDER BY updated_at DESC',
      [user_id]
    );
    return res.rows;
  },
};

// ════════════════════════════════════════════════════════════════════════
// AUDIT LOG
// ════════════════════════════════════════════════════════════════════════

const AuditLog = {
  async log({ user_id, action, target_id, target_type, details, ip_address }) {
    try {
      await pool.query(
        'INSERT INTO audit_log (user_id,action,target_id,target_type,details,ip_address) VALUES ($1,$2,$3,$4,$5,$6)',
        [user_id||null, action, target_id||null, target_type||null, details ? JSON.stringify(details) : null, ip_address||null]
      );
    } catch(e) { console.error('[AuditLog] Failed:', e.message); }
  },
  async getRecent(limit = 100) {
    const res = await pool.query(
      `SELECT al.*, u.email AS actor_email
       FROM audit_log al LEFT JOIN users u ON u.id=al.user_id
       ORDER BY al.created_at DESC LIMIT $1`,
      [limit]
    );
    return res.rows;
  },
};

// ════════════════════════════════════════════════════════════════════════
// STATS
// ════════════════════════════════════════════════════════════════════════

const Stats = {
  async getOverview() {
    const res = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users WHERE status='active')                   AS active_users,
        (SELECT COUNT(*) FROM users WHERE role IN ('superadmin','admin'))     AS admins,
        (SELECT COUNT(*) FROM searches)                                       AS total_searches,
        (SELECT COUNT(*) FROM reports)                                        AS total_reports,
        (SELECT ROUND(AVG(risk_score)) FROM searches WHERE risk_score IS NOT NULL) AS avg_risk_score,
        (SELECT COUNT(*) FROM searches WHERE risk_level='CRITICAL')           AS critical_scans,
        (SELECT COUNT(*) FROM searches WHERE created_at > NOW()-INTERVAL '7 days') AS searches_7d
    `);
    return res.rows[0];
  },
};

// ════════════════════════════════════════════════════════════════════════
// ADMIN PANEL DATA
// ════════════════════════════════════════════════════════════════════════

const Admin = {
  // Check if caller has required role
  checkRole(userRole, required = 'admin') {
    const levels = { user: 0, admin: 1, superadmin: 2 };
    if ((levels[userRole] || 0) < (levels[required] || 1)) {
      throw Object.assign(new Error('Insufficient permissions'), { code: 403 });
    }
  },

  // Full admin dashboard
  async getDashboard() {
    const [stats, users, searches, reports, auditLog] = await Promise.all([
      Stats.getOverview(),
      Users.getActivitySummary(),
      Searches.getAll({ limit: 20 }),
      Reports.getAll({ limit: 20 }),
      AuditLog.getRecent(50),
    ]);
    return { stats, users, searches, reports, auditLog };
  },
};

module.exports = { pool, testConnection, Users, Searches, Reports, Notes, AuditLog, Stats, Admin, makeToken, verifyToken };
