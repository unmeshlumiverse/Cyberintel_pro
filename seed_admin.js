// ================================================================
// seed_admin.js — Seeds the superadmin account with correct hashing
// Run: node seed_admin.js
// ================================================================

// Load .env manually — no dotenv package needed
const fs = require('fs');
const path = require('path');
try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx < 1) return;
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
      if (key && !process.env[key]) process.env[key] = val;
    });
  }
} catch(e) {}

const { Pool } = require('pg');
const crypto = require('crypto');

const pool = new Pool({
  host:     process.env.PGHOST     || 'localhost',
  port:     parseInt(process.env.PGPORT || '5432'),
  database: process.env.PGDATABASE || 'cyberintel_pro',
  user:     process.env.PGUSER     || 'postgres',
  
});

function hashPassword(password, salt) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(key.toString('hex')))
  );
}

const USERS_TO_SEED = [
  {
    email:        'ba@lumiversesolutions.com',
    password: process.env.ADMIN_PASSWORD,   // ← CHANGE AFTER FIRST LOGIN
    name:         'Lumiverse Admin',
    company_name: 'Lumiverse Solutions Pvt. Ltd.',
    role:         'superadmin',
    must_change:  false,
  },
  // Add more users here if needed:
  // { email: 'user@example.com', password: 'Temp@1234', name: 'John', company_name: 'Acme', role: 'user', must_change: true },
];

async function seed() {
  console.log('\n[Seed] Connecting to PostgreSQL...');
  
  try {
    const client = await pool.connect();
    console.log('[Seed] Connected to:', process.env.PGDATABASE || 'cyberintel_pro');
    
    for (const u of USERS_TO_SEED) {
      const key  = u.email.toLowerCase().trim();
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = await hashPassword(u.password, salt);
      const id   = crypto.randomUUID();
      
      // Upsert — update if exists, insert if not
      const res = await client.query(`
        INSERT INTO users (id, email, password_hash, salt, name, company_name, role, status, must_change_pwd, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, NOW())
        ON CONFLICT (email) DO UPDATE SET
          password_hash   = EXCLUDED.password_hash,
          salt            = EXCLUDED.salt,
          name            = EXCLUDED.name,
          company_name    = EXCLUDED.company_name,
          role            = EXCLUDED.role,
          must_change_pwd = EXCLUDED.must_change_pwd,
          updated_at      = NOW()
        RETURNING id, email, role, status
      `, [id, key, hash, salt, u.name, u.company_name, u.role, u.must_change]);
      
      console.log(`[Seed] ✅  ${res.rows[0].email} | role: ${res.rows[0].role} | id: ${res.rows[0].id}`);
      console.log(`[Seed]     Password: ${u.password}  ${u.must_change ? '(user must change on first login)' : '(no forced change)'}`);
    }
    
    // Show all users
    const all = await client.query('SELECT email, role, status, created_at FROM users ORDER BY created_at');
    console.log('\n[Seed] All users in database:');
    console.table(all.rows);
    
    client.release();
    await pool.end();
    console.log('\n[Seed] Done! You can now log in with the credentials above.\n');
  } catch(e) {
    console.error('[Seed] Error:', e.message);
    if (e.message.includes('password authentication')) {
      console.error('[Seed] → Wrong postgres password. Edit PGPASSWORD in .env file');
    } else if (e.message.includes('does not exist')) {
      console.error('[Seed] → Database not found. Run: psql -U postgres -f database_setup.sql');
    } else if (e.message.includes('ECONNREFUSED')) {
      console.error('[Seed] → PostgreSQL not running. Start it with: pg_ctl start');
    }
    process.exit(1);
  }
}

seed();
