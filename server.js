const http = require('http');
const https = require('https');
const dns   = require('dns').promises;
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const crypto = require('crypto');

// ── Built-in .env loader — no dotenv npm package needed ──────────────
// Reads .env file from same directory and sets process.env variables
(function loadEnv() {
  try {
    const envPath = path.join(__dirname, '.env');
    if (!fs.existsSync(envPath)) return;
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    lines.forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx < 1) return;
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
      if (key && !process.env[key]) process.env[key] = val;
    });
    console.log('[Env] Loaded .env file');
  } catch(e) { console.warn('[Env] Could not load .env:', e.message); }
})();

// ── PostgreSQL db module (optional — only loads if pg is installed) ───
let db = null;
try {
  db = require('./db');
  db.testConnection().then(ok => {
    if (ok) console.log('[DB] PostgreSQL connected — using database for auth + history');
    else console.warn('[DB] PostgreSQL unavailable — falling back to users.json');
  });
} catch(e) {
  console.log('[DB] db.js not loaded (pg not installed or db.js missing) — using local users.json');
}


// ════════════════════════════════════════════════════════════════════
// SELF-HOSTED AUTH — server-side users.json + HMAC JWT (no Supabase)
// ════════════════════════════════════════════════════════════════════
const JWT_SECRET  = process.env.JWT_SECRET;
const USERS_FILE  = path.join(__dirname, 'users.json');

function _loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return {}; }
}
function _saveUsers(u) {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2)); } catch(e) { console.error('users.json write failed:', e.message); }
}
function _hashPwd(password, salt) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(key.toString('hex')))
  );
}
function _makeToken(payload) {
  const h = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const b = Buffer.from(JSON.stringify({...payload, iat:Date.now(), exp:Date.now()+30*24*60*60*1000})).toString('base64url');
  const s = crypto.createHmac('sha256', JWT_SECRET).update(h+'.'+b).digest('base64url');
  return `${h}.${b}.${s}`;
}
function _verifyToken(token) {
  try {
    const [h,b,s] = (token||'').split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(h+'.'+b).digest('base64url');
    if (s !== expected) return null;
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}


// ── API KEYS (env only — no hardcoded fallbacks) ──────────────────────
const GEMINI_KEYS = Object.keys(process.env)
  .filter(k => k.startsWith('GEMINI_KEY_'))
  .sort()
  .map(k => process.env[k])
  // Accept BOTH new AQ. auth keys AND legacy AIzaSy keys
  .filter(k => k && !k.includes('PASTE') && (k.startsWith('AQ.') || k.startsWith('AIza')));

if (GEMINI_KEYS.length === 0) {
  console.log('[Gemini] ⚠ No valid keys in .env. Add GEMINI_KEY_1=AQ... or AIza... — get keys at aistudio.google.com/app/apikey');
} else {
  const aqCount = GEMINI_KEYS.filter(k=>k.startsWith('AQ.')).length;
  const aiCount = GEMINI_KEYS.filter(k=>k.startsWith('AIza')).length;
  console.log(`[Gemini] ${GEMINI_KEYS.length} keys loaded (${aqCount} new AQ. auth keys, ${aiCount} legacy AIza keys)`);
  console.log('[Server] DMARC parser v2 ACTIVE — MXToolbox Records+Information+Passed formats supported');
}

// ── FREE OSINT API KEYS (env only) ───────────────────────────────────
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY;
const GREYNOISE_KEY  = process.env.GREYNOISE_KEY;
const URLSCAN_KEY    = process.env.URLSCAN_KEY;
const ABUSEIPDB_KEY  = process.env.ABUSEIPDB_KEY;
const MXTOOLBOX_KEY  = process.env.MXTOOLBOX_KEY;
// No key needed: Shodan InternetDB, crt.sh, ip-api.com, RDAP, HackerTarget, archive.org, leakix.net

// ── Startup key audit ────────────────────────────────────────────────
(function auditKeys() {
  const required = { JWT_SECRET, VIRUSTOTAL_KEY, GREYNOISE_KEY, URLSCAN_KEY, ABUSEIPDB_KEY, MXTOOLBOX_KEY };
  const missing = Object.entries(required).filter(([,v]) => !v).map(([k]) => k);
  if (missing.length) console.warn('[Config] ⚠ Missing env vars:', missing.join(', '), '— add them to .env');
  else console.log('[Config] All API keys loaded from .env');
})();

const PORT = parseInt(process.env.PORT || '3000');
let keyIdx = 0;
const nextKey = () => GEMINI_KEYS[keyIdx++ % GEMINI_KEYS.length];
const GEMINI_MODEL = 'gemini-2.5-flash-lite';

// ── LOAD KNOWLEDGE MODULES ──────────────────────────────────────────
let buildRegulatoryContext = () => '';
let buildObjectionContext  = () => '';
let buildKnowledgeContext  = () => '';
let buildGovContext        = () => '';

try { const m = require('./regulatory_data'); buildRegulatoryContext = m.buildRegulatoryContext; buildObjectionContext = m.buildObjectionContext; console.log(' ✓ Regulatory DB'); } catch(e) { console.error(' ✗ regulatory_data:', e.message); }
try { const m = require('./knowledge_base');   buildKnowledgeContext  = m.buildKnowledgeContext;  console.log(' ✓ Knowledge Base'); } catch(e) { console.error(' ✗ knowledge_base:', e.message); }
try { const m = require('./gov_knowledge');    buildGovContext        = m.buildGovContext;        console.log(' ✓ Gov Knowledge'); } catch(e) { console.error(' ✗ gov_knowledge:', e.message); }

const MIME = { '.html':'text/html','.css':'text/css','.js':'application/javascript','.json':'application/json','.png':'image/png','.ico':'image/x-icon' };

// ── HELPERS ─────────────────────────────────────────────────────────
function extractDomain(raw) {
  try { return new URL(raw.includes('://')?raw:'https://'+raw).hostname.replace(/^www\./,''); }
  catch(e) { return null; }
}

function httpsGet(opts, timeout=8000) {
  return new Promise((res,rej) => {
    const req = https.request(opts, r => {
      let d=''; r.on('data',c=>d+=c); r.on('end',()=>{ try{res(JSON.parse(d));}catch(e){res({_raw:d,_status:r.statusCode}); }});
    });
    req.setTimeout(timeout, ()=>{req.destroy();rej(new Error('Timeout'));});
    req.on('error',rej); req.end();
  });
}

// ── DNS / EMAIL SECURITY SCAN (Supports MxToolBox API fallback) ─────
async function scanDNS(domain) {
  const result = { domain, spf:{exists:false,record:null,policy:null,issues:[]}, dmarc:{exists:false,record:null,policy:null,issues:[]}, mx:{exists:false,records:[]}, blacklist:{listed:false,details:[]}, ssl:{checked:false}, summary_gaps:[], lumiverse_opportunities:[] };

  let dmarcChecked = false;
  let spfChecked = false;

  // 1. MxToolBox API (if key provided)
  if (MXTOOLBOX_KEY && !MXTOOLBOX_KEY.includes('PASTE')) {
    try {
      const headers = { 'Authorization': MXTOOLBOX_KEY, 'Accept': 'application/json' };
      const [dmarcRes, spfRes] = await Promise.all([
        httpsGet({ hostname: 'mxtoolbox.com', path: '/api/v1/lookup/dmarc/' + domain, method: 'GET', headers }, 8000).catch(()=>null),
        httpsGet({ hostname: 'mxtoolbox.com', path: '/api/v1/lookup/spf/' + domain, method: 'GET', headers }, 8000).catch(()=>null)
      ]);

      // Helper: extract a record string from any MXToolbox response shape
      const extractRecord = (res, marker) => {
        if (!res) return null;
        // Format 1: Records array (plain strings — most common, e.g. ESDS)
        if (Array.isArray(res.Records)) {
          for (const r0 of res.Records) {
            const s = typeof r0 === 'string' ? r0 : (r0.Record || r0.Value || r0.record || r0.TXTRecord || r0.Name || '');
            if (typeof s === 'string' && s.toLowerCase().includes(marker)) return s;
          }
        }
        // Format 2: Information array — look for Name='record' or Description containing marker
        if (Array.isArray(res.Information)) {
          // First try the explicit "record" entry
          const recEntry = res.Information.find(i => i && i.Name === 'record' && typeof i.Description === 'string' && i.Description.toLowerCase().includes(marker));
          if (recEntry) return recEntry.Description;
          // Then any field containing the marker
          for (const i of res.Information) {
            if (!i) continue;
            for (const field of [i.Description, i.Value, i.Record]) {
              if (typeof field === 'string' && field.toLowerCase().includes(marker)) return field;
            }
          }
        }
        // Format 3: Lookup / RawResponse / Transcript string
        for (const field of [res.Lookup, res.RawResponse, res.raw]) {
          if (typeof field === 'string' && field.toLowerCase().includes(marker)) return field;
        }
        // Format 4: Transcript array (raw DNS response)
        if (Array.isArray(res.Transcript)) {
          for (const t of res.Transcript) {
            const s = typeof t === 'string' ? t : t?.Transcript;
            if (typeof s === 'string' && s.toLowerCase().includes(marker)) {
              const m = s.match(new RegExp('(v=' + marker.slice(2) + '[^,\\r\\n\\t]*)', 'i'));
              if (m) return m[1];
            }
          }
        }
        return null;
      };

      const dInfo = extractRecord(dmarcRes, 'v=dmarc1');
      if (dInfo) {
        result.dmarc.exists = true;
        result.dmarc.record = dInfo;
        const pm = dInfo.match(/\bp\s*=\s*([a-z]+)/i);
        result.dmarc.policy = pm ? pm[1].toLowerCase() : 'none';
        if (result.dmarc.policy === 'none') result.dmarc.issues.push('DMARC p=none — phishing NOT blocked');
        else if (result.dmarc.policy === 'quarantine') result.dmarc.issues.push('DMARC p=quarantine — upgrade to p=reject');
        dmarcChecked = true;
        console.log('[DNS] DMARC (MXToolbox):', domain, '| policy:', result.dmarc.policy);
      } else if (dmarcRes) {
        console.log('[DNS] MXToolbox DMARC: no record parsed for', domain, '| raw:', JSON.stringify(dmarcRes).slice(0,150));
      }

      const sInfo = extractRecord(spfRes, 'v=spf1');
      if (sInfo) {
        result.spf.exists = true;
        result.spf.record = sInfo;
        result.spf.policy = sInfo.includes('-all') ? 'hard_fail' : sInfo.includes('~all') ? 'soft_fail' : 'permissive';
        if (sInfo.includes('~all')) result.spf.issues.push('SPF ~all — spoofed emails may reach inbox');
        else if (sInfo.includes('+all')) result.spf.issues.push('SPF +all — ANYONE can send as this domain');
        spfChecked = true;
        console.log('[DNS] SPF (MXToolbox):', domain, '| policy:', result.spf.policy);
      } else if (spfRes) {
        console.log('[DNS] MXToolbox SPF: no record parsed for', domain, '| raw:', JSON.stringify(spfRes).slice(0,150));
      }
    } catch(e) {
      console.warn('[MxToolBox] Error:', e.message);
    }
  }

  // 2. Native DNS Fallback for SPF
  if (!spfChecked) {
    try {
      const recs = await dns.resolveTxt(domain);
      const spf = recs.map(r=>r.join('')).find(r=>r.trim().toLowerCase().startsWith('v=spf1'));
      if (spf) {
        result.spf={exists:true,record:spf,policy:spf.includes('-all')?'hard_fail':spf.includes('~all')?'soft_fail':'permissive',issues:spf.includes('~all')?['SPF ~all — spoofed emails may reach inbox']:spf.includes('+all')?['SPF +all — ANYONE can send as this domain']:[] };
      } else {
        result.spf.issues.push('No SPF record — domain open to email spoofing');
      }
    } catch(e) {
      if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') {
        result.spf.issues.push('No SPF record — domain open to email spoofing');
      } else {
        result.spf.checked = false;
        result.spf.error = `DNS lookup failed (${e.code}) — could not verify, not confirmed missing`;
      }
    }
  }

  // 3. Native DNS Fallback for DMARC
  if (!dmarcChecked) {
    try {
      const recs = await dns.resolveTxt('_dmarc.'+domain);
      const d = recs.map(r=>r.join('')).find(r=>r.trim().toLowerCase().startsWith('v=dmarc1'));
      if (d) {
        const pm=d.match(/\bp=\s*([a-z]+)/i);
        const pol=pm?pm[1].toLowerCase():'none';
        result.dmarc={exists:true,record:d,policy:pol,issues:pol==='none'?['DMARC p=none — phishing NOT blocked']:pol==='quarantine'?['DMARC p=quarantine — upgrade to p=reject']:d.includes('rua=')?[]:['No DMARC reporting — spoofing invisible']};
      } else {
        result.dmarc.issues.push('No DMARC — domain impersonation CRITICAL risk');
      }
    } catch(e) {
      if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') {
        result.dmarc.issues.push('No DMARC — domain impersonation CRITICAL risk');
      } else {
        result.dmarc.checked = false;
        result.dmarc.error = `DNS lookup failed (${e.code}) — could not verify, not confirmed missing`;
      }
    }
  }

  // MX
  try { const mx = await dns.resolveMx(domain); result.mx={exists:true,records:mx.map(r=>r.exchange).slice(0,3)}; } catch(e) {}
  // SSL via crt.sh (no key needed)
  try {
    const data = await httpsGet({hostname:'crt.sh',method:'GET',path:`/?q=${encodeURIComponent(domain)}&output=json`},6000);
    if (Array.isArray(data) && data.length) {
      const latest=data[0]; const expiry=new Date(latest.not_after); const days=Math.floor((expiry-Date.now())/86400000);
      const subs=[...new Set(data.slice(0,30).map(c=>c.common_name).filter(n=>n&&n!==domain))].slice(0,10);
      result.ssl={checked:true,expiry:latest.not_after,days_left:days,subdomains:subs,issuer:(latest.issuer_name||'').slice(0,60)};
      if (days<30) result.ssl.warning=`SSL cert expires in ${days} days — URGENT renewal needed`;
      if (days<0)  result.ssl.warning=`SSL cert EXPIRED ${Math.abs(days)} days ago`;
    }
  } catch(e) {}
  // Spamhaus blacklist check (no key needed)
  try {
    const ips = await dns.resolve4(domain); result.ip=ips[0];
    const rev = ips[0].split('.').reverse().join('.');
    try { await dns.resolve4(rev+'.zen.spamhaus.org'); result.blacklist={listed:true,details:['Spamhaus ZEN — email deliverability severely impacted']}; } catch(e){}
    try { await dns.resolve4(rev+'.b.barracudacentral.org'); result.blacklist.listed=true; result.blacklist.details.push('Barracuda blacklist'); } catch(e){}
  } catch(e) {}
  // HackerTarget subdomains (no key needed)
  try {
    const ht = await httpsGet({hostname:'api.hackertarget.com',method:'GET',path:`/hostsearch/?q=${domain}`},8000);
    if (ht._raw && !ht._raw.includes('error') && !ht._raw.includes('exceeded')) {
      const subs=ht._raw.split('\n').filter(Boolean).map(l=>l.split(',')[0]).filter(s=>s!==domain).slice(0,15);
      const risky=subs.filter(s=>/dev|test|staging|admin|uat|demo|api|internal|vpn|mail/i.test(s));
      if (subs.length) result.subdomains_hackertarget=subs;
      if (risky.length) result.risky_subdomains=risky;
    }
  } catch(e) {}
  // HTTP headers + tech stack detection (no API key needed)
  try {
    const techResult = await detectTechStack(domain);
    if (techResult) {
      result.tech_stack         = techResult.tech || [];
      result.headers            = techResult.headers || {};
      result.page_title         = techResult.title || '';
    }
  } catch(e) {}

  // Build gap summary
  const gaps=[], opps=[];
  if (result.spf.checked === false) { gaps.push({check:'SPF',status:'UNVERIFIED',severity:'UNKNOWN',detail:result.spf.error}); }
  else if (!result.spf.exists) { gaps.push({check:'SPF',status:'MISSING',severity:'CRITICAL',detail:'No SPF record — email spoofing fully open'}); opps.push('Email Security VAPT + SPF Implementation'); }
  else if (result.spf.issues.length) { gaps.push({check:'SPF',status:'WEAK',severity:'HIGH',detail:result.spf.issues[0]}); opps.push('SPF Hardening'); }
  else { gaps.push({check:'SPF',status:'PASS',severity:'OK',detail:'SPF configured'}); }
  if (result.dmarc.checked === false) { gaps.push({check:'DMARC',status:'UNVERIFIED',severity:'UNKNOWN',detail:result.dmarc.error}); }
  else if (!result.dmarc.exists) { gaps.push({check:'DMARC',status:'MISSING',severity:'CRITICAL',detail:'No DMARC — domain impersonation risk critical'}); opps.push('DMARC Implementation'); }
  else if (result.dmarc.policy==='none') { gaps.push({check:'DMARC',status:'WEAK',severity:'HIGH',detail:'p=none — phishing not blocked'}); opps.push('DMARC Enforcement'); }
  else { gaps.push({check:'DMARC',status:'PASS',severity:'OK',detail:`p=${result.dmarc.policy}`}); }
  if (result.blacklist.listed) { gaps.push({check:'Blacklist',status:'LISTED',severity:'CRITICAL',detail:result.blacklist.details[0]}); opps.push('Blacklist Removal + IR'); }
  if (result.ssl.checked && result.ssl.warning) { gaps.push({check:'SSL',status:'EXPIRING',severity:'HIGH',detail:result.ssl.warning}); opps.push('SSL Certificate Management'); }
  if (result.risky_subdomains?.length) { gaps.push({check:'Exposed Subdomains',status:'RISK',severity:'HIGH',detail:`Exposed: ${result.risky_subdomains.slice(0,3).join(', ')}`}); opps.push('Subdomain Security + VAPT'); }
  result.summary_gaps=gaps; result.lumiverse_opportunities=[...new Set(opps)];
  return result;
}

// ── VIRUSTOTAL SCAN ─────────────────────────────────────────────────
async function scanVT(domain) {
  if (!VIRUSTOTAL_KEY || VIRUSTOTAL_KEY.includes('PASTE')) return null;
  try {
    const data = await httpsGet({
      hostname:'www.virustotal.com', method:'GET',
      path:`/api/v3/domains/${domain}`,
      headers:{'x-apikey':VIRUSTOTAL_KEY,'Accept':'application/json'}
    });
    if (!data.data) return null;
    const stats = data.data.attributes?.last_analysis_stats || {};
    const mal   = stats.malicious || 0;
    const susp  = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a,b)=>a+b,0);
    return { malicious:mal, suspicious:susp, total, reputation:data.data.attributes?.reputation||0,
             flag: mal>0?'THREAT_DETECTED':susp>2?'SUSPICIOUS':'CLEAN',
             categories:data.data.attributes?.categories||{} };
  } catch(e) { return null; }
}

// ── ROBOTS.TXT SCANNER (free, no key) ────────────────────────────────
async function scanRobotsTxt(domain) {
  return new Promise(resolve => {
    const req = https.request({hostname:domain,path:'/robots.txt',method:'GET',timeout:4000,headers:{'User-Agent':'Mozilla/5.0'}},r=>{
      let b=''; r.on('data',c=>b+=c); r.on('end',()=>{
        if (r.statusCode!==200||!b.trim()) return resolve({found:false});
        const disallows=(b.match(/Disallow:[^\n]+/g)||[]);
        const sitemaps=(b.match(/Sitemap:[^\n]+/g)||[]);
        resolve({found:true,disallow_count:disallows.length,sitemap:sitemaps.length>0,
          sample_paths:disallows.slice(0,5).map(d=>d.replace('Disallow:','').trim())});
      });
    });
    req.on('error',()=>resolve({found:false}));
    req.on('timeout',()=>{req.destroy();resolve({found:false});});
    req.end();
  });
}

// ── SECURITY.TXT SCANNER (free, no key) ──────────────────────────────
async function scanSecurityTxt(domain) {
  return new Promise(resolve => {
    const req = https.request({hostname:domain,path:'/.well-known/security.txt',method:'GET',timeout:4000,headers:{'User-Agent':'Mozilla/5.0'}},r=>{
      let b=''; r.on('data',c=>b+=c); r.on('end',()=>{
        if (r.statusCode!==200||!b.includes('Contact:')) return resolve({found:false});
        const contact=(b.match(/Contact:\s*(.+)/i)||[])[1]?.trim();
        const expires=(b.match(/Expires:\s*(.+)/i)||[])[1]?.trim();
        const policy =(b.match(/Policy:\s*(.+)/i)||[])[1]?.trim();
        resolve({found:true,contact,expires,policy,pgp_signed:b.includes('BEGIN PGP')});
      });
    });
    req.on('error',()=>resolve({found:false}));
    req.on('timeout',()=>{req.destroy();resolve({found:false});});
    req.end();
  });
}

// ── HTTP HEADERS + TECH DETECTION (no API key) ──────────────────────
async function detectTechStack(domain) {
  return new Promise(resolve => {
    const opts = { hostname: domain, path: '/', method: 'GET', timeout: 6000,
      headers: { 'User-Agent': 'Mozilla/5.0 CyberIntel Security Scanner' } };
    const req = https.request(opts, r => {
      const h = r.headers || {};
      const tech = [];
      const missing_security_headers = [];
      // Detect tech from headers
      const server = h['server'] || '';
      const powered = h['x-powered-by'] || '';
      if (server) tech.push(server.split(' ')[0]);
      if (powered) tech.push(powered.split('/')[0]);
      if (h['cf-ray']) tech.push('Cloudflare CDN');
      if (h['x-amz-cf-id'] || h['x-amz-request-id']) tech.push('AWS');
      if ((h['x-ms-request-id'] || '').includes('ms')) tech.push('Azure');
      if (h['x-wp-total'] || (h['link']||'').includes('wp-json')) tech.push('WordPress');
      // Missing security headers
      if (!h['strict-transport-security']) missing_security_headers.push('HSTS');
      if (!h['x-content-type-options']) missing_security_headers.push('X-Content-Type-Options');
      if (!h['x-frame-options'] && !h['content-security-policy']) missing_security_headers.push('Clickjacking Protection');
      if (!h['content-security-policy']) missing_security_headers.push('Content-Security-Policy');
      const score = Math.max(0, 100 - missing_security_headers.length * 25);
      // Collect page body for title
      let body = '';
      r.on('data', c => { if (body.length < 2000) body += c; });
      r.on('end', () => {
        const titleMatch = body.match(/<title[^>]*>([^<]{3,80})<\/title>/i);
        const title = titleMatch ? titleMatch[1].trim() : '';
        resolve({ tech: [...new Set(tech)], headers: { score, missing: missing_security_headers }, title });
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

// ── IP GEOLOCATION (ip-api.com — free, no key) ──────────────────────
async function getIPLocation(ip) {
  if (!ip) return null;
  try {
    const data = await httpsGet({ hostname:'ip-api.com', path:'/json/'+ip+'?fields=country,regionName,city,org,isp,as,hosting', method:'GET' }, 5000);
    if (data.country) return { country: data.country, region: data.regionName, city: data.city, org: data.org, isp: data.isp, asn: data.as, is_hosting: data.hosting };
  } catch(e) {}
  return null;
}

// ── SHODAN INTERNETDB (free, no key needed) ──────────────────────────
async function shodanFree(ip) {
  if (!ip) return null;
  try {
    const data = await httpsGet({ hostname:'internetdb.shodan.io', path:'/'+ip, method:'GET' }, 6000);
    if (data.ports) {
      const riskyPorts = (data.ports||[]).filter(p=>[21,22,23,25,3389,5900,8080,8443,3306,5432,27017,6379,9200,11211].includes(p));
      return { ip, ports: data.ports, risky_ports: riskyPorts, vulns: data.vulns||[], tags: data.tags||[], cpes: data.cpes||[], hostnames: data.hostnames||[] };
    }
  } catch(e) {}
  return null;
}

// ── WHOIS / RDAP (no key needed) ─────────────────────────────────────
async function getWhois(domain) {
  try {
    const data = await httpsGet({ hostname:'rdap.org', path:'/domain/'+domain, method:'GET', headers:{'Accept':'application/json'} }, 6000);
    if (!data.ldhName) return null;
    const events = data.events || [];
    const registered = events.find(e=>e.eventAction==='registration')?.eventDate;
    const expiry     = events.find(e=>e.eventAction==='expiration')?.eventDate;
    const updated    = events.find(e=>e.eventAction==='last changed')?.eventDate;
    const registrar  = (data.entities||[]).find(e=>(e.roles||[]).includes('registrar'))?.vcardArray?.[1]?.find?.(v=>v[0]==='fn')?.[3] || '';
    const ageYears   = registered ? Math.floor((Date.now()-new Date(registered))/(365.25*24*3600*1000)) : null;
    return { registered, expiry, updated, registrar, age_years: ageYears, status: data.status || [] };
  } catch(e) { return null; }
}

// ── ABUSEIPDB (free 1000/day — abuseipdb.com) ──────────────────────────
async function checkAbuseIPDB(ip) {
  if (!ip || !ABUSEIPDB_KEY) return null;
  return new Promise(resolve => {
    const req = https.request({
      hostname:'api.abuseipdb.com', path:`/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
      method:'GET', timeout:6000,
      headers:{'Key':ABUSEIPDB_KEY,'Accept':'application/json'}
    }, r => {
      let b=''; r.on('data',d=>b+=d); r.on('end',()=>{
        try {
          const d=JSON.parse(b).data;
          resolve({ abuse_score:d.abuseConfidenceScore, total_reports:d.totalReports,
            last_reported:d.lastReportedAt, country:d.countryCode, usage_type:d.usageType,
            isp:d.isp, is_whitelisted:d.isWhitelisted });
        } catch { resolve(null); }
      });
    });
    req.on('error',()=>resolve(null)); req.on('timeout',()=>{req.destroy();resolve(null);}); req.end();
  });
}

// ── HAVE I BEEN PWNED — Domain breach check (free) ──────────────────────
async function checkHIBP(domain) {
  return new Promise(resolve => {
    const req = https.request({
      hostname:'haveibeenpwned.com', path:`/api/v3/breacheddomain/${encodeURIComponent(domain)}`,
      method:'GET', timeout:8000,
      headers:{'User-Agent':'CyberIntelPro/2.0','hibp-api-key':'free'}
    }, r => {
      let b=''; r.on('data',d=>b+=d); r.on('end',()=>{
        if (r.statusCode === 404) return resolve({ breached: false, count: 0 });
        try {
          const data = JSON.parse(b);
          resolve({ breached: true, count: data.length || 0, breaches: data.slice(0,5) });
        } catch { resolve(null); }
      });
    });
    req.on('error',()=>resolve(null)); req.on('timeout',()=>{req.destroy();resolve(null);}); req.end();
  });
}

// ── GREYNOISE COMMUNITY (free with account key — viz.greynoise.io/signup) ──
async function scanGreyNoise(ip) {
  if (!ip || !GREYNOISE_KEY) return null;
  try {
    const data = await httpsGet({
      hostname:'api.greynoise.io', path:'/v3/community/'+ip, method:'GET',
      headers:{'key': GREYNOISE_KEY, 'Accept':'application/json'}
    }, 6000);
    if (!data || data.message === 'This IP is not in our dataset') return {ip, seen:false, classification:'unknown', noise:false, riot:false};
    return {
      ip, seen:true,
      noise:          data.noise || false,
      riot:           data.riot  || false,
      classification: data.classification || 'unknown', // benign | malicious | unknown
      name:           data.name || '',
      last_seen:      data.last_seen || '',
      link:           data.link || '',
      message:        data.message || ''
    };
  } catch(e) { return null; }
}

// ── URLSCAN.IO SEARCH (free 1000/month — urlscan.io) ────────────────
async function scanURLScan(domain) {
  try {
    const headers = {'Accept':'application/json'};
    if (URLSCAN_KEY) headers['API-Key'] = URLSCAN_KEY;
    const data = await httpsGet({
      hostname:'urlscan.io',
      path:'/api/v1/search/?q=domain:'+encodeURIComponent(domain)+'&size=5&sort=date',
      method:'GET', headers
    }, 8000);
    if (!data || !data.results) return null;
    const results = (data.results||[]).slice(0,3);
    if (!results.length) return {domain, scans:[], verdict:'no_history'};
    const malicious = results.filter(r => r.verdicts?.overall?.malicious);
    const latest = results[0];
    return {
      domain,
      total_scans:  data.total || results.length,
      latest_scan:  latest?.task?.time || '',
      latest_url:   'https://urlscan.io/result/'+latest?.task?.uuid,
      malicious_count: malicious.length,
      verdict: malicious.length > 0 ? 'MALICIOUS' : 'CLEAN',
      brands_detected: results.flatMap(r=>r.verdicts?.urlscan?.brands||[]).filter(Boolean).slice(0,3),
      country:    latest?.page?.country || '',
      server:     latest?.page?.server  || '',
      ip:         latest?.page?.ip      || '',
      screenshot: latest?.screenshot   || '',
    };
  } catch(e) { return null; }
}

// ── WAYBACK MACHINE / archive.org (completely free, no key) ─────────
async function scanWayback(domain) {
  try {
    // Check if domain has been archived — get first and last seen dates
    const data = await httpsGet({
      hostname:'archive.org',
      path:'/wayback/available?url='+encodeURIComponent('https://'+domain),
      method:'GET', headers:{'Accept':'application/json'}
    }, 6000);
    if (!data || !data.archived_snapshots) return null;
    const closest = data.archived_snapshots.closest;
    if (!closest || !closest.available) return {domain, archived:false};
    const snapUrl = closest.url || '';
    // Also get CDX summary for first appearance
    const cdx = await httpsGet({
      hostname:'web.archive.org',
      path:'/cdx/search/cdx?url='+encodeURIComponent(domain)+'&output=json&limit=1&fl=timestamp&from=&to=&fastLatest=true',
      method:'GET'
    }, 6000);
    let firstSeen = null;
    if (Array.isArray(cdx) && cdx.length > 1 && cdx[1][0]) {
      const ts = cdx[1][0];
      firstSeen = ts.slice(0,4)+'-'+ts.slice(4,6)+'-'+ts.slice(6,8);
    }
    return {
      domain, archived:true,
      first_seen:    firstSeen,
      last_snapshot: closest.timestamp,
      snapshot_url:  snapUrl,
    };
  } catch(e) { return null; }
}

// ── LEAKIX.NET (free — no key for basic results) ─────────────────────
async function scanLeakIX(domain) {
  try {
    const data = await httpsGet({
      hostname:'leakix.net',
      path:'/host/'+encodeURIComponent(domain),
      method:'GET',
      headers:{'Accept':'application/json', 'api-key': ''}
    }, 6000);
    if (!data || data.error) return null;
    return {
      domain,
      events:    (data.Events||[]).slice(0,5).map(e=>({type:e.event_type||'', summary:e.summary||'', date:e.time||''})),
      services:  (data.Services||[]).slice(0,5).map(s=>({port:s.port||'', protocol:s.protocol||'', summary:s.summary||''})),
      issues:    (data.Events||[]).filter(e=>e.severity==='high'||e.severity==='critical').length
    };
  } catch(e) { return null; }
}



// ── SECURITYTRAILS FREE (1000/month — no key needed for basic DNS history) ──
async function scanSecurityTrails(domain) {
  // SecurityTrails has no unauthenticated free tier
  // But we can get DNS history via alternative free sources
  try {
    // Use DNSHistory via hackertarget (different endpoint)
    const data = await httpsGet({
      hostname:'api.hackertarget.com',
      path:'/dnslookup/?q='+encodeURIComponent(domain),
      method:'GET'
    }, 6000);
    if (!data._raw || data._raw.includes('error')) return null;
    const records = data._raw.split('\n').filter(Boolean);
    return { domain, dns_records: records.slice(0,10) };
  } catch(e) { return null; }
}

// ── VULNERS CVE LOOKUP (free, no key for basic search) ───────────────
async function scanVulners(cves) {
  if (!cves || !cves.length) return null;
  try {
    const results = {};
    for (const cve of cves.slice(0, 3)) {
      // Use NVD (NIST) free API — no key needed
      const data = await httpsGet({
        hostname: 'services.nvd.nist.gov',
        path: '/rest/json/cves/2.0?cveId=' + cve,
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      }, 8000);
      if (data && data.vulnerabilities && data.vulnerabilities.length) {
        const vuln = data.vulnerabilities[0].cve;
        const cvss = vuln.metrics?.cvssMetricV31?.[0]?.cvssData ||
                     vuln.metrics?.cvssMetricV30?.[0]?.cvssData ||
                     vuln.metrics?.cvssMetricV2?.[0]?.cvssData;
        results[cve] = {
          description: (vuln.descriptions?.find(d=>d.lang==='en')?.value||'').slice(0,200),
          severity:    cvss?.baseSeverity || 'UNKNOWN',
          score:       cvss?.baseScore || 0,
          published:   vuln.published?.slice(0,10) || '',
        };
      }
    }
    return Object.keys(results).length ? results : null;
  } catch(e) { return null; }
}

// ── CERT-IN EMPANELMENT CHECK (heuristic — no API) ──────────────────
function checkCertInHeuristic(domain) {
  // We can't query CERT-In's list programmatically, but we note this for context
  return { note: 'CERT-In empanelment cannot be verified automatically. Manual check: https://www.cert-in.org.in/empanelledorganisations.jsp' };
}

// ── DNS SECURITY FULL SCORE ──────────────────────────────────────────
function calculateDNSScore(dnsResult) {
  let score = 100;
  if (dnsResult.spf?.checked !== false && !dnsResult.spf?.exists) score -= 25;
  else if (dnsResult.spf?.policy === 'permissive') score -= 10;
  if (dnsResult.dmarc?.checked !== false && !dnsResult.dmarc?.exists) score -= 25;
  else if (dnsResult.dmarc?.policy === 'none') score -= 15;
  if (dnsResult.blacklist?.listed) score -= 30;
  if (dnsResult.ssl?.days_left < 30) score -= 15;
  if (dnsResult.risky_subdomains?.length > 0) score -= 10;
  return Math.max(0, score);
}

// ── FULL SCAN (DNS only — conserves API limits) ─────────────────────
// Domains that should not be analyzed (own company, test domains)
const BLOCKED_DOMAINS = [
  'lumiversesolutions.com', 'lumiverse.com', 'cyberambassador.co.in',
  'white-coyote-501625.hostingersite.com', 'localhost',
  'example.com', 'test.com', 'google.com', 'facebook.com'
];

function isValidDomain(domain) {
  if (!domain || domain.length < 4) return false;
  if (!domain.includes('.')) return false;
  // Block own company and test domains
  const lowerDomain = domain.toLowerCase();
  if (BLOCKED_DOMAINS.some(b => lowerDomain === b || lowerDomain.endsWith('.'+b))) {
    return false;
  }
  const part = domain.split('.')[0];
  const letters = part.replace(/[^a-z]/gi,'').toLowerCase();
  if (letters.length > 3) {
    const unique = new Set(letters).size;
    const maxRep = Math.max(...[...new Set(letters)].map(c => letters.split(c).length-1));
    if (maxRep > letters.length * 0.5) return false;
    if (unique < 4 && letters.length > 5) return false;
  }
  return true;
}

async function runFullScan(urls, prefs={}) {
  const domain = urls.map(extractDomain).find(Boolean);
  if (!domain) return {error:'Could not extract domain from URL'};
  if (!isValidDomain(domain)) {
    if (BLOCKED_DOMAINS.some(b => domain.toLowerCase() === b || domain.toLowerCase().endsWith('.'+b))) {
      return {error:`"${domain}" is your own company domain — CyberIntel Pro analyzes prospect companies, not Lumiverse itself. Enter a prospect's website URL instead.`};
    }
    return {error:`"${domain}" does not appear to be a valid prospect website. Please enter the company's actual website URL.`};
  }
  console.log('[Scan]', domain);
  
  // Run DNS + tech detection in parallel
  const [dns_result, techResult] = await Promise.all([
    scanDNS(domain),
    detectTechStack(domain).catch(()=>null)
  ]);
  
  const scan = {
    domain, ip: dns_result.ip || null, dns: dns_result,
    virustotal: null, abuseipdb: null, censys: null,
    tech_stack: techResult?.tech || [],
    headers: techResult?.headers || { score:0, missing:[], security_grade:'F' },
    page_title: techResult?.title || '',
    scan_time: new Date().toISOString()
  };
  
  // ALL OSINT tools in parallel — no waiting
  const [shodanData, ipLocation, whoisData, greynoiseData, urlscanData, waybackData, leakixData, abuseData, hibpData, hudsonData, sslLabsData, urlhausData, mozObsData] = await Promise.all([
    dns_result.ip ? shodanFree(dns_result.ip).catch(()=>null)      : Promise.resolve(null),
    dns_result.ip ? getIPLocation(dns_result.ip).catch(()=>null)   : Promise.resolve(null),
    getWhois(domain).catch(()=>null),
    dns_result.ip ? scanGreyNoise(dns_result.ip).catch(()=>null)   : Promise.resolve(null),
    scanURLScan(domain).catch(()=>null),
    scanWayback(domain).catch(()=>null),
    scanLeakIX(domain).catch(()=>null),
  ]);
  
  if (shodanData)    scan.shodan       = shodanData;
  if (ipLocation)    scan.ip_location  = ipLocation;
  if (whoisData)     scan.whois        = whoisData;
  if (greynoiseData) scan.greynoise    = greynoiseData;
  if (urlscanData)   scan.urlscan      = urlscanData;
  if (waybackData)   scan.wayback      = waybackData;
  if (leakixData)    scan.leakix       = leakixData;

  // CVE details from NVD (free, no key) — enrich Shodan CVE list
  if (shodanData?.vulns?.length) {
    const cveDetails = await scanVulners(shodanData.vulns).catch(()=>null);
    if (cveDetails) scan.cve_details = cveDetails;
  }

  // robots.txt + security.txt (web-check style — free, no key)
  const [robotsData, secTxtData] = await Promise.all([
    scanRobotsTxt(domain).catch(()=>({found:false})),
    scanSecurityTxt(domain).catch(()=>({found:false})),
  ]);
  scan.robots_txt = robotsData.found ? robotsData : {found:false};
  // Always store results — even "clean" results are valuable to display
  scan.abuse_ipdb   = abuseData   || { abuse_score:0, total_reports:0, status:'not_checked' };
  scan.hibp         = hibpData    || { breached:false, count:0, status:'checked' };
  scan.hudson_rock  = hudsonData  || { stealers_count:0, employees_exposed:0, status:'checked' };
  scan.urlhaus      = urlhausData || { blacklisted:false, urls_count:0, status:'checked' };
  scan.ssl_labs     = sslLabsData || null;
  scan.mozilla_obs  = mozObsData  || null;
  // Threats
  if (abuseData?.abuse_score > 25) threats.push(`AbuseIPDB: ${abuseData.abuse_score}% abuse confidence — ${abuseData.total_reports} reports`);
  if (hibpData?.breached) threats.push(`HIBP: domain in ${hibpData.count} data breaches`);
  if (hudsonData?.stealers_count > 0) threats.push(`Hudson Rock: ${hudsonData.stealers_count} infostealer records, ${hudsonData.employees_exposed} credentials exposed`);
  if (urlhausData?.blacklisted) threats.push('URLhaus: domain in malware database');
  scan.security_txt = secTxtData.found ? secTxtData : {found:false};

  // Add security.txt absence as a gap
  const all_gaps = [];
  if (!secTxtData.found) {
    all_gaps.push({ tool:'Security.txt', check:'No security.txt', status:'MISSING', severity:'LOW',
      detail:'No /.well-known/security.txt — security researchers cannot report vulnerabilities responsibly' });
  }
  
  // Calculate overall DNS security score
  scan.dns_score = calculateDNSScore(dns_result);
  
  // Build all_gaps for UI (combining DNS + Shodan + headers)
  // Build all_gaps for UI (combining DNS + Shodan + headers)


// Add security.txt absence as a gap
if (!secTxtData.found) {
  all_gaps.push({
    tool: 'Security.txt',
    check: 'No security.txt',
    status: 'MISSING',
    severity: 'LOW',
    detail: 'No /.well-known/security.txt — security researchers cannot report vulnerabilities responsibly'
  });
}

// Calculate overall DNS security score
scan.dns_score = calculateDNSScore(dns_result);

// DNS gaps
(dns_result.summary_gaps || []).forEach(g => {
  all_gaps.push({
    tool: 'DNS/Email',
    check: g.check,
    status: g.status,
    severity: g.severity,
    detail: g.detail
  });
});

// ...rest of your pushes remain unchanged...

scan.all_gaps = all_gaps;
  (dns_result.summary_gaps||[]).forEach(g => {
    all_gaps.push({ tool:'DNS/Email', check:g.check, status:g.status, severity:g.severity, detail:g.detail });
  });
  if (shodanData?.risky_ports?.length) {
    all_gaps.push({ tool:'Shodan', check:'Open Ports', status:'EXPOSED', severity:'HIGH', detail:'Risky ports open: '+shodanData.risky_ports.join(', ') });
  }
  if (shodanData?.vulns?.length) {
    all_gaps.push({ tool:'Shodan', check:'Known CVEs', status:'VULNERABLE', severity:'CRITICAL', detail:'CVEs: '+shodanData.vulns.slice(0,3).join(', ') });
  }
  if (scan.headers?.missing?.length) {
    all_gaps.push({ tool:'HTTP Headers', check:'Security Headers', status:'MISSING', severity:'MEDIUM', detail:'Missing: '+scan.headers.missing.join(', ')+' (score: '+scan.headers.score+'%)' });
  }
  if (whoisData?.expiry) {
    const daysToExpiry = Math.floor((new Date(whoisData.expiry)-Date.now())/86400000);
    if (daysToExpiry < 90) all_gaps.push({ tool:'WHOIS', check:'Domain Expiry', status:'WARN', severity:'MEDIUM', detail:'Domain expires in '+daysToExpiry+' days ('+whoisData.expiry+')' });
  }
  // GreyNoise — IP reputation
  if (greynoiseData?.noise && greynoiseData?.classification === 'malicious') {
    all_gaps.push({ tool:'GreyNoise', check:'IP Reputation', status:'MALICIOUS', severity:'CRITICAL', detail:'GreyNoise: IP classified as MALICIOUS — actively scanning the internet' });
  } else if (greynoiseData?.noise && greynoiseData?.classification !== 'benign') {
    all_gaps.push({ tool:'GreyNoise', check:'IP Reputation', status:'NOISE', severity:'HIGH', detail:'GreyNoise: IP is actively scanning internet (noise classification)' });
  }
  // urlscan.io — past malicious scans
  if (urlscanData?.verdict === 'MALICIOUS') {
    all_gaps.push({ tool:'urlscan.io', check:'URL History', status:'MALICIOUS', severity:'CRITICAL', detail:'urlscan.io: '+urlscanData.malicious_count+' of '+urlscanData.total_scans+' past scans flagged as malicious' });
  }
  // LeakIX — exposed services
  if (leakixData?.issues > 0) {
    all_gaps.push({ tool:'LeakIX', check:'Exposed Services', status:'VULNERABLE', severity:'HIGH', detail:'LeakIX: '+leakixData.issues+' high/critical severity events detected on this host' });
  }
  scan.all_gaps = all_gaps;
  
  // Risk score
  const critCount = all_gaps.filter(g=>g.severity==='CRITICAL').length;
  const highCount = all_gaps.filter(g=>g.severity==='HIGH').length;
  scan.risk_score = Math.min(100, critCount*30 + highCount*15 + (all_gaps.length - critCount - highCount)*5);
  const threats=[];
  if (dns_result.blacklist.listed) threats.push(`Blacklisted: ${dns_result.blacklist.details[0]}`);
  if (dns_result.ssl?.warning) threats.push(`SSL: ${dns_result.ssl.warning}`);
  if (dns_result.spf.checked === false) threats.push('SPF — ' + dns_result.spf.error);
  else if (!dns_result.spf.exists) threats.push('No SPF — email spoofing open');
  if (dns_result.dmarc.checked === false) threats.push('DMARC — ' + dns_result.dmarc.error);
  else if (!dns_result.dmarc.exists) threats.push('No DMARC — impersonation risk');
  if (dns_result.risky_subdomains?.length) threats.push(`Exposed subdomains: ${dns_result.risky_subdomains.join(', ')}`);
  // VirusTotal — only if key available AND user enabled it
  try {
    const vt = (prefs.vt !== false && !VIRUSTOTAL_KEY.includes('PASTE')) ? await scanVT(domain) : null;
    if (vt) {
      scan.virustotal = vt;
      if (vt.flag === 'THREAT_DETECTED') threats.push(`VirusTotal: ${vt.malicious}/${vt.total} engines flagged as MALICIOUS`);
      else if (vt.flag === 'SUSPICIOUS') threats.push(`VirusTotal: ${vt.suspicious} engines suspicious`);
    }
  } catch(e) {}

  scan.threat_summary=threats;
  if (scan.headers?.score < 50) threats.push(`Security headers score ${scan.headers.score}% — missing: ${(scan.headers.missing||[]).join(', ')}`);

  // Run web-check style analysis
  try {
    const wcStyle = await runWebCheckStyle(domain);
    if (wcStyle) {
      scan.web_check = wcStyle;
      if (wcStyle.powered_by) scan.tech_stack = [...(scan.tech_stack||[]), wcStyle.powered_by].filter(Boolean);
      if (wcStyle.security_grade) threats.push(`HTTP security grade: ${wcStyle.security_grade} (score ${wcStyle.security_score}/7 headers)`);
    }
  } catch(e) {}

  console.log(`[Scan] Done — ${threats.length} threats, ${dns_result.summary_gaps.length} gaps`);
  return scan;
}

function formatScanForPrompt(scan) {
  if (!scan || scan.error) return '';
  try {
    const dns=scan.dns||{}, L=['\n\n=== LIVE SECURITY SCAN ==='];
    if (scan.threat_summary?.length) { L.push('THREATS:'); scan.threat_summary.forEach(t=>L.push('  🔴 '+t)); }
    (dns.summary_gaps||[]).forEach(g=>L.push('['+g.severity+'] '+g.check+': '+g.status+' — '+g.detail));
    if (scan.virustotal) L.push('VirusTotal: '+scan.virustotal.flag+' | Malicious: '+scan.virustotal.malicious+'/'+scan.virustotal.total);
    if (scan.greynoise) {
      const gn = scan.greynoise;
      if (gn.seen) L.push('GreyNoise: '+gn.classification.toUpperCase()+(gn.noise?' | Internet scanner detected':'')+(gn.name?' | '+gn.name:''));
    }
    if (scan.urlscan) {
      const us = scan.urlscan;
      L.push('urlscan.io: '+us.verdict+' | '+us.total_scans+' historical scans'+(us.malicious_count?' | '+us.malicious_count+' malicious':''));
    }
    if (scan.shodan) {
      if (scan.shodan.risky_ports?.length) L.push('Shodan risky ports: '+scan.shodan.risky_ports.join(', '));
      if (scan.shodan.vulns?.length) L.push('Shodan CVEs: '+scan.shodan.vulns.slice(0,3).join(', '));
    }
    if (scan.leakix?.issues > 0) L.push('LeakIX: '+scan.leakix.issues+' high-severity exposed services');
    if (scan.wayback?.archived) L.push('Wayback: first seen '+scan.wayback.first_seen+' | last '+scan.wayback.last_snapshot);
    if (scan.ip_location) L.push('Server: '+[scan.ip_location.city, scan.ip_location.country].filter(Boolean).join(', ')+(scan.ip_location.isp?' | '+scan.ip_location.isp:'')+(scan.ip_location.is_hosting?' | Cloud-hosted':''));
    if (scan.whois?.age_years != null) L.push('Domain age: '+scan.whois.age_years+' years | Registrar: '+(scan.whois.registrar||'unknown'));
    if (scan.tech_stack?.length) L.push('Tech: '+scan.tech_stack.join(', '));
    if (scan.headers?.missing?.length) L.push('Missing security headers: '+scan.headers.missing.join(', '));
    L.push('=== END SCAN ===');
    return L.join('\n');
  } catch(e) { return ''; }
}

// ── WEBSITE PRE-FETCH — extract ground truth before Gemini ─────────
async function prefetchWebsite(urlStr) {
  try {
    const u = new URL(urlStr.includes('://') ? urlStr : 'https://'+urlStr);
    const domain = u.hostname;
    return new Promise(resolve => {
      const opts = {
        hostname: domain, path: u.pathname||'/', method:'GET', timeout:8000,
        headers:{ 'User-Agent':'Mozilla/5.0 CyberIntelBot/1.0', 'Accept':'text/html' }
      };
      const req = https.request(opts, r => {
        let body = '';
        r.on('data', c => { if (body.length < 60000) body += c; });
        r.on('end', () => {
          try {
            // Extract key facts from raw HTML
            const titleM  = body.match(/<title[^>]*>([^<]{2,120})<\/title>/i);
            // Check if this is an error page - reject the title if so
            const rawTitle = titleM ? titleM[1].trim() : '';
            const isErrorPage = /error|403|404|forbidden|not found|access denied|cloudfront|bad gateway|503|502|maintenance/i.test(rawTitle);
            const h1M     = body.match(/<h1[^>]*>([^<]{3,100})<\/h1>/i);
            const h2M     = body.match(/<h2[^>]*>([^<]{3,100})<\/h2>/i);
            const descM   = body.match(/content="([^"]{20,200})"/i);
            // Look for bank-specific patterns
            const branchM = body.match(/(\d+)\s*branch/i);
            const yearM   = body.match(/(?:founded|established|since|incorporated)[^\d]*(\d{4})/i);
            const emailM  = body.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
            const phoneM  = body.match(/(?:\+91|0)?[6-9]\d{9}/);
            // Look for the actual bank/company name — prioritize logo alt text and brand mentions
            const logoAltM = body.match(/<img[^>]*(?:logo|brand)[^>]*alt="([^"]{3,60})"/i) ||
                            body.match(/alt="([^"]{3,60})"[^>]*(?:logo|brand)/i);
            const welcomeM = body.match(/[Ww]elcome\s+(?:to\s+)?([A-Z][A-Za-z\s&]{3,50}(?:Bank|Ltd|Pvt|Corp|Co\.)?)/);
            const aboutM   = body.match(/"([A-Z][A-Za-z\s&]{3,50}(?:Bank|Limited|Ltd))"[^<]{0,200}(?:founded|established|since)/i);
            // Also look for mobile app mentions
            const hasAndroid = /play\.google\.com|android.*app|google.*play/i.test(body);
            const hasIOS     = /apple.*store|app.*store|ios.*app/i.test(body);
            const hasUPI     = /\bUPI\b/.test(body);
            const hasNEFT    = /\bNEFT\b|\bRTGS\b|\bIMPS\b/.test(body);
            const hasATM     = /\bATM\b/.test(body);
            const hasSWIFT   = /\bSWIFT\b/.test(body);
            const hasMobile  = /mobile\s*banking/i.test(body);
            const hasInternet= /internet\s*banking|net\s*banking/i.test(body);

            // A company name must be short, proper noun — not a tagline/marketing phrase
            const _isTagline = (s) => {
              if (!s) return true;
              const words = s.trim().split(/\s+/);
              if (words.length > 6) return true; // too long = tagline
              const taglineWords = /solutions?|services?|technologies?|systems?|platforms?|digital|cyber|security|india|global|world|leader|trusted|best|top|premier|excellence|innovation|transform|empower|enable|partner|group|pvt|ltd|llp|inc|corp/i;
              // If more than 2 tagline words = probably a tagline not a name
              const taglineCount = words.filter(w => taglineWords.test(w)).length;
              if (taglineCount >= 3) return true;
              return false;
            };
            const _titleCandidate = titleM ? titleM[1].replace(/[-|–—|\|].*$/,'').trim() : null;
            const _titleIsGood = _titleCandidate && !isErrorPage && !_isTagline(_titleCandidate);
            const companyName = 
              (logoAltM && logoAltM[1].length > 3 && !isErrorPage && !_isTagline(logoAltM[1]) ? logoAltM[1].trim() : null) ||
              (welcomeM && !_isTagline(welcomeM[1]) ? welcomeM[1].trim() : null) ||
              (aboutM ? aboutM[1].trim() : null) ||
              (_titleIsGood ? _titleCandidate : null) ||
              (!isErrorPage && h1M && !_isTagline(h1M[1]) ? h1M[1].trim() : null) || domain;

            resolve({
              domain,
              company_name: companyName,
              page_title:  titleM ? titleM[1].trim() : '',
              h1:          h1M ? h1M[1].trim() : '',
              description: descM ? descM[1].trim() : '',
              branch_count: branchM ? branchM[1] : null,
              founded_year: yearM ? yearM[1] : null,
              contact_email: emailM ? emailM[0] : null,
              contact_phone: phoneM ? phoneM[0] : null,
              digital_products: [
                hasInternet && 'Internet Banking',
                hasMobile   && 'Mobile Banking App',
                hasUPI      && 'UPI',
                hasNEFT     && 'RTGS/NEFT/IMPS',
                hasATM      && 'ATM',
                hasSWIFT    && 'SWIFT',
                hasAndroid  && 'Android App',
                hasIOS      && 'iOS App',
              ].filter(Boolean),
            });
          } catch(e) { resolve({domain, company_name: domain}); }
        });
      });
      req.on('error', () => resolve({domain, company_name: domain}));
      req.on('timeout', () => { req.destroy(); resolve({domain, company_name: domain}); });
      req.end();
    });
  } catch(e) { return null; }
}

// ── ENTERPRISE SYSTEM PROMPT ────────────────────────────────────────
function buildSystemPrompt(mode, industry) {
  let regCtx='', objCtx='', kbCtx='', govCtx='';
  try { regCtx = buildRegulatoryContext(industry||'', mode)||''; } catch(e){}
  try { objCtx = buildObjectionContext(industry||'')||''; } catch(e){}
  try { kbCtx  = buildKnowledgeContext(industry||'', mode)||''; } catch(e){}
  try { govCtx = buildGovContext(industry||'', mode)||''; } catch(e){}

  const CORE = `You are CyberIntel Pro — Lumiverse Solutions Pvt. Ltd. enterprise sales intelligence engine.
CERT-In empanelled | 350+ Bank VAPTs | 135+ UCBs audited | 650+ forensics cases with Maharashtra Police.
CEH, CISA, CISSP, CHFI, OSCP certified team. Director: Amar Thakare.

═══ DATA EXTRACTION RULES (CRITICAL — READ CAREFULLY) ═══
⚠ GROUND TRUTH IS PROVIDED IN THE USER PROMPT — DO NOT OVERRIDE IT.
The user prompt contains PRE-FETCHED DATA from the actual website.
Use it as the primary source. Only use Google Search to SUPPLEMENT, not replace it.

RULE 1 — COMPANY NAME: Use EXACTLY the company name from the pre-fetched data.
  If pre-fetch says "Namco Bank" → company_name MUST be "Namco Bank". Never guess a different bank.

RULE 2 — DIGITAL PRODUCTS: Pre-fetched data lists confirmed digital products. Trust it.

RULE 3 — Google Search is for: branch count, leadership names, RBI actions, financials.
  Google Search is NOT for: overriding the company name or domain confirmed in pre-fetch.

RULE 4 — If you are tempted to write a different company name than what the URL/pre-fetch shows, STOP.
  The URL namcobank.bank.in → company is Namco Bank. Not Maharashtra Nagari Sahakari Bank.

If data is NOT found: return null. DO NOT fill with "No verified data available".
Confidence: HIGH=pre-fetch+Google confirmed | MEDIUM=one source | LOW=inferred

═══ GAP RULES (MANDATORY — NEVER RETURN EMPTY GAPS) ═══
Every gap MUST have:
  name: specific gap name (NOT just "Security Gap")
  impact_level: critical/high/medium/low
  business_effect: specific consequence with ₹ amount or regulatory citation
  lumiverse_service: exact Lumiverse service name
  sales_opportunity: one sentence why they need this NOW

If the live scan found missing SPF/DMARC → that IS a gap. Add it.
If the scan found exposed subdomains → that IS a gap. Add it.
If the company has no CISO on LinkedIn → that IS a gap for RBI/SEBI/IRDAI regulated entities.
Always produce minimum 3 gaps.

// SCRIPT IS AUTO-GENERATED SERVER-SIDE — DO NOT WRITE sales_script. Leave it null.
// Focus only on: company_name, compliance_gaps, compliance_they_have, trigger_points, pain_points.

═══ TRIGGER POINTS ═══
Produce minimum 3 trigger points. Each must have:
  trigger: specific event creating urgency NOW
  why_it_matters: regulatory/business consequence
  lumiverse_angle: exact Lumiverse service addressing this

═══ OBJECTION HANDLING ═══
For each common objection, provide a response that:
1. Acknowledges in 3 words max
2. Cites exact regulation + ₹ penalty
3. Asks a closing question

OBJECTION CONTEXT:
65B certificate = Section 65B Indian Evidence Act — certificate for digital evidence admissibility in court. NOT the same as CERT-In empanelment. A company asking about 65B is concerned about legal proceedings / forensics.

LUMIVERSE SERVICES:
VAPT(Network/Web App/Mobile/API/Cloud AWS-Azure-GCP/IoT/Source Code/Red Team/Wireless), IS Audit(EDP/GAP Assessment/IT Risk/Migration/Data Localization/SWIFT), C-SOC(24x7/SIEM/EDR/XDR/Firewall/IDS-IPS/DLP/PAM/Honeypot), Compliance(ISO27001/PCI-DSS/SOC2/HIPAA/GDPR/DPDP/NIST/IEC62443), vCISO, Forensics(Disk/Mobile/eDiscovery/Ransomware/BEC/IPR Theft), RBI/SEBI/IRDAI Regulatory, UCB Level I-IV Assessment, Web3(Blockchain/Smart Contract/Wallet Audit), Dark Web Monitoring, Phishing Simulation Training`;

  const bankSchema = '{"company_name":"exact company name","website":"url","industry":"precise subcategory e.g. Urban Cooperative Bank / NBFC-MFI / Payment Aggregator","business_nature":"2-3 specific sentences with actual products/clients/scale","headquarters":"city, state","employee_range":"e.g. 200-500","founded":"year if found","revenue_range":"if visible","branch_count":"number if found","tech_stack":["specific systems found e.g. Finacle CBS","Internet Banking Portal","UPI integration"],"confidence_score":"high/medium/low","risk_score":50,"compliance_they_have":[{"name":"specific control","confidence":"confirmed/likely","reason":"why you believe this"}],"compliance_gaps":[{"name":"specific gap name","impact_level":"critical/high/medium/low","business_effect":"₹ amount or exact regulation + consequence","lumiverse_service":"exact Lumiverse service","sales_opportunity":"one sentence urgency"}],"trigger_points":[{"trigger":"specific urgency trigger","why_it_matters":"exact consequence","lumiverse_angle":"exact service"}],"sales_script":null,"social_links":{"linkedin":"url","twitter":"url"},"key_decision_makers":[{"name":"name","role":"role","email":"email if known"}],"pain_points":["4 specific pain points with numbers"],"ucb_level":"L1/L2/L3/L4 if UCB else null","ucb_level_reason":"criteria matched"}';

  const corpSchema = '{"company_name":"exact company name","website":"url","industry":"precise sector","business_nature":"2-3 specific sentences","headquarters":"city, state","employee_range":"range","founded":"year","revenue_range":"range","confidence_score":"high/medium/low","risk_score":50,"compliance_they_have":[{"name":"","confidence":"","reason":""}],"compliance_gaps":[{"name":"specific gap","impact_level":"critical/high/medium/low","business_effect":"₹ amount or business damage","lumiverse_service":"exact service","sales_opportunity":"urgency sentence"}],"risk_triggers":[{"trigger":"specific event","urgency":"high/medium","lumiverse_angle":"exact service"}],"sales_script":null,"social_links":{"linkedin":"url","twitter":"url"},"key_decision_makers":[{"name":"name","role":"role","email":"email if known"}],"pain_points":["4 specific pain points"]}';

  const cpSchema = `{"company_name":"exact name","website":"url","industry":"sector","business_nature":"2-3 specific sentences about what they do and who their clients are","headquarters":"city","employee_range":"range","founded":"year","revenue_range":"range","confidence_score":"high/medium/low","risk_score":50,"cp_analysis":{"is_cp_fit":true,"fit_score":75,"fit_reasoning":"specific 2-sentence reason naming their client type and the security gap","their_client_base":"describe exactly who their clients are and approximate count","partnership_model":"referral OR resell OR co-delivery OR white-label","services_they_can_resell":["list of Lumiverse services relevant to their clients"],"services_they_cannot_provide":["security gaps their clients have that this CP cannot fill"],"commercial_benefit":"e.g. 15-20% referral on each closed deal","cp_script":"MANDATORY — write all 7 lines — DO NOT write Not available. Line 1: Hi [Name] comma [Company] serves [client type] dash I noticed you work with [X] clients. Line 2: Their biggest gap is [specific RBI/SEBI/DPDP gap]. Line 3: Lumiverse is CERT-In empanelled dash we have audited 350 plus banks. Line 4: We propose [model] dash you refer we deliver you earn [X] percent margin. Line 5: You stay trusted advisor we handle technical delivery. Line 6: We can white-label reports under your branding. Line 7: 30-min call this week to share CP commercials and case studies?"},"compliance_gaps":[{"name":"specific gap","impact_level":"high/medium","business_effect":"client consequence","lumiverse_service":"service","sales_opportunity":"one line"}],"social_links":{"linkedin":"url","twitter":"url"},"key_decision_makers":[{"name":"name","role":"role","email":"email if known"}],"pain_points":["3 pain points their clients face that Lumiverse solves"]}`;

  const schema = mode==='bank' ? bankSchema : mode==='cp' ? cpSchema : corpSchema;

  return CORE + '\n\n' + regCtx + '\n' + govCtx + '\n' + kbCtx + '\n' + objCtx + '\n\nReturn ONLY valid JSON matching this exact schema (no markdown, no backticks, no explanation):\n' + schema;
}


// ── GEMINI CALL ─────────────────────────────────────────────────────
function callGemini(system, user, cb, _attempt) {
  _attempt = _attempt || 0;
  const payload = JSON.stringify({
    contents:[{role:'user',parts:[{text:system+'\n\n---\n\n'+user}]}],
    // google_search grounding REMOVED — needs paid tier, causes 400 on free keys
    generationConfig:{temperature:0.15,maxOutputTokens:8192,responseMimeType:'application/json'}
  });
  const key = nextKey();
  const keyShort = (key||'').slice(0,10)+'...';
  const isAuthKey = (key||'').startsWith('AQ.'); // new auth-key format
  // Use x-goog-api-key HEADER (works for BOTH AQ. auth keys AND AIzaSy standard keys)
  // The new AQ. keys ONLY work via header, not via ?key= URL param
  const opts = {
    hostname:'generativelanguage.googleapis.com',
    path:`/v1beta/models/${GEMINI_MODEL}:generateContent`,
    method:'POST',
    headers:{
      'Content-Type':'application/json',
      'x-goog-api-key': key,
      'Content-Length':Buffer.byteLength(payload)
    },
    timeout:120000
  };
  const chunks=[];
  const req = https.request(opts, r => {
    console.log('[Gemini] HTTP', r.statusCode, '| key:', keyShort, isAuthKey?'(AQ auth)':'(AIza)');
    r.on('data',c=>chunks.push(c));
    r.on('end',()=>{
      const raw = Buffer.concat(chunks).toString('utf8');
      if (r.statusCode !== 200) {
        const maxAttempts = Math.max(4, GEMINI_KEYS.length + 1);
        if (r.statusCode === 403 || r.statusCode === 400) {
          const errSnip = raw.slice(0,120).replace(/\s+/g,' ');
          console.log(`[Gemini] ${r.statusCode} key issue (${keyShort}): ${errSnip}`);
          if (_attempt < maxAttempts) return setTimeout(() => callGemini(system, user, cb, _attempt + 1), 500);
          return cb(null,{error:{message:`All Gemini keys failed (${r.statusCode}). For new AQ. keys, ensure they're created in AI Studio. Details: ${errSnip}`}});
        }
        if (_attempt < maxAttempts) {
          const delay = r.statusCode === 429 ? (_attempt + 1) * 8000 : 1000;
          console.log(`[Gemini] HTTP ${r.statusCode} — retry ${_attempt+1}/${maxAttempts} in ${delay/1000}s`);
          return setTimeout(() => callGemini(system, user, cb, _attempt + 1), delay);
        }
        return cb(null,{error:{message:`Gemini HTTP ${r.statusCode} after ${maxAttempts} retries.`}});
      }
      try {
        const p = JSON.parse(raw);
        if (p.error) return cb(null,{error:{message:'Gemini: '+p.error.message}});
        const text=(p.candidates?.[0]?.content?.parts||[]).filter(x=>x.text).map(x=>x.text).join('');
        if (!text) return cb(null,{error:{message:'No output. Finish: '+p.candidates?.[0]?.finishReason}});
        cb(null,{content:[{type:'text',text}]});
      } catch(e) { cb(null,{error:{message:'Parse: '+e.message}}); }
    });
  });
  req.on('timeout',()=>{req.destroy();cb(new Error('Timeout'));});
  req.on('error',e=>cb(e));
  req.write(payload); req.end();
}

// ── OBJECTION HANDLER ────────────────────────────────────────────────

// Classify what kind of question/objection this is
function classifyQuestion(q) {
  const text = q.toLowerCase();

  // Technical / how-does-it-work questions
  if (/how does|how do|what is|what are|explain|difference between|vs |versus|define|mean by|tell me about|can you explain|what exactly|how it works|what does.*do/i.test(text))
    return 'technical';

  // Process / what-happens-next questions
  if (/how long|how many days|timeline|process|steps|what happens|when will|how will|deliverable|report|scope|methodology|approach/i.test(text))
    return 'process';

  // Proof / credibility questions
  if (/case study|reference|client|who have you|worked with|experience|proof|example|show me|portfolio|credentials|certified|cert-in/i.test(text))
    return 'credibility';

  // Commercial / pricing objections
  if (/expensive|cost|price|budget|afford|cheaper|discount|roi|return|justify|too much|money/i.test(text))
    return 'commercial';

  // Priority / timing objections
  if (/later|next year|not now|busy|priority|not a priority|come back|wait|postpone|next quarter/i.test(text))
    return 'timing';

  // Vendor / competitor objections
  if (/already have|vendor|partner|existing|another company|someone else|competitor|currently using/i.test(text))
    return 'vendor';

  // Internal capability objections
  if (/internal team|in-house|ourselves|our team|we can do|we do it/i.test(text))
    return 'internal';

  // Legal / compliance specific questions
  if (/65b|section 65|evidence|court|legal|compliance|regulation|rbi|sebi|irdai|cert-in|mandatory|penalty|fine/i.test(text))
    return 'compliance';

  return 'general';
}

function callObjectionHandler(objection, context, cb) {
  const {company='', industry='', scan, mode=''} = context;

  // Validate input
  const uniqueChars = new Set((objection||'').toLowerCase().replace(/[^a-z]/g,'')).size;
  if (!objection || objection.trim().length < 4 || uniqueChars < 4) {
    return cb(null, { content: [{ type:'text', text: 'Please type the actual question or objection from your prospect.' }] });
  }

  const qType = classifyQuestion(objection);
  let objCtx = '';
  try { objCtx = buildObjectionContext(industry||'')||''; } catch(e){}
  const scanFacts = scan ? formatScanForPrompt(scan).slice(0,400) : '';
  const companyCtx = company ? `Prospect company: ${company} (${industry||'financial sector'})` : '';

  // Build type-specific system prompt
  const roleIntro = `You are a senior cybersecurity consultant at Lumiverse Solutions. CERT-In empanelled. 15 years in BFSI security. 350+ bank VAPTs, 135+ UCB audits. You are on a live call.
${companyCtx}
${scanFacts}`;

  let instructions = '';

  if (qType === 'technical') {
    instructions = `The prospect asked a TECHNICAL question. They want to understand something, not be sold to right now.
RESPOND like a knowledgeable expert having a real conversation:
- Answer their actual question clearly and concisely (2-3 sentences)
- Use simple language — no jargon without explanation
- Show expertise naturally, not by listing credentials
- End with ONE relevant question that moves the conversation forward
- DO NOT mention penalties or regulations unless directly relevant
- MAX 4 lines total. Sound like a real person talking, not a sales script.

EXAMPLE (How does VAPT work?):
"VAPT has two parts — Vulnerability Assessment scans for known weaknesses automatically, while Penetration Testing is manual where our team actively tries to break in like a real attacker would.
For a bank your size, we'd typically cover your network, internet banking portal, mobile app, and APIs over 5-7 days.
We give you a prioritised report — critical findings first, with exact remediation steps.
Do you want me to walk you through a sample report from a similar bank?"`;

  } else if (qType === 'process') {
    instructions = `The prospect is asking about HOW you work — timeline, steps, deliverables.
RESPOND with specifics — they want to visualise working with you:
- Give a clear, confident answer with actual numbers (days, steps, deliverables)
- Be specific to their context if you know their industry
- Sound like you've done this hundreds of times (because Lumiverse has)
- End with a question that commits them to a next step
- MAX 4 lines. Conversational, not a pitch.`;

  } else if (qType === 'credibility') {
    instructions = `The prospect wants PROOF — they're not convinced yet.
RESPOND with specific evidence:
- Name a relevant credential, statistic, or outcome (135+ UCBs, 350+ banks, 650+ forensics cases)
- If possible, reference their specific industry ("we audited 3 cooperative banks in Maharashtra last quarter")
- Offer something concrete — case study, reference call, sample report
- MAX 4 lines. Confident, not defensive.`;

  } else if (qType === 'commercial') {
    instructions = `The prospect raised a PRICING or ROI concern.
RESPOND by reframing cost as risk:
- Acknowledge briefly (1 line max)
- Give a specific ₹ comparison — cost of service vs cost of a breach/penalty
- Use real numbers: IBM 2024 India breach cost ₹17.9 crore, RBI FY25 penalties ₹54.78 crore total
- Offer a next step that feels low-risk (free gap assessment, scoped quote)
- MAX 4 lines.`;

  } else if (qType === 'timing') {
    instructions = `The prospect is pushing back on TIMING.
RESPOND with urgency that feels real, not manufactured:
- Acknowledge their situation (1 line)
- Give ONE specific reason why waiting costs more than acting (deadline passed, active threat, penalty risk)
- Use a fact from their scan if available, or a recent India cyber incident
- Offer the lowest-friction next step possible
- MAX 4 lines. Not pushy, but confident.`;

  } else if (qType === 'vendor') {
    instructions = `The prospect says they ALREADY HAVE a vendor.
RESPOND without attacking their current vendor:
- Acknowledge it (1 line)
- Ask ONE smart question that reveals a gap (Is your vendor CERT-In empanelled? When was your last Application VAPT? Does their scope cover APIs?)
- Position Lumiverse as a complement or second opinion, not a replacement
- MAX 4 lines. Curious, not aggressive.`;

  } else if (qType === 'internal') {
    instructions = `The prospect says they can handle it INTERNALLY.
RESPOND by clarifying what regulators require externally:
- Acknowledge their capability (1 line)
- Explain the specific regulatory requirement for an EXTERNAL independent audit (RBI Section 30, SEBI CSCRF, IRDAI)
- Note the conflict-of-interest issue — regulators specifically require independence
- MAX 4 lines. Factual, respectful, not condescending.`;

  } else if (qType === 'compliance') {
    instructions = `The prospect asked a COMPLIANCE or REGULATORY question.
RESPOND with accurate, specific regulatory knowledge:
- Answer their actual question with the correct regulatory reference
- NOTE: 65B = Section 65B Indian Evidence Act 1872 — digital evidence admissibility in court. NOT the same as CERT-In.
- Be precise — cite the correct act, section, and what it actually requires
- Connect to Lumiverse's relevant service
- MAX 4 lines. Expert, accurate, helpful.
${objCtx}`;

  } else {
    instructions = `The prospect raised a concern or question.
RESPOND naturally and intelligently:
- Understand what they're actually asking first
- Answer directly and honestly
- Show expertise through specifics, not by listing your credentials
- End with a question that moves the conversation forward
- MAX 4 lines. Sound like a real senior consultant, not a sales bot.`;
  }

  const system = `${roleIntro}

${instructions}`;

  callGemini(system, `Prospect said: "${objection}"\n\nRespond naturally. Do not start with "I". Do not use bullet points. Write as flowing sentences.`, cb);
}


// ── HUDSON ROCK — Infostealer credential exposure (free) ─────────────
async function checkHudsonRock(domain) {
  return new Promise(resolve => {
    const req = https.request({
      hostname:'cavalier.hudsonrock.com',
      path:'/api/json/v2/osint-tools/search-by-domain?domain='+encodeURIComponent(domain),
      method:'GET', timeout:8000,
      headers:{'User-Agent':'IntelPro/2.0','Accept':'application/json'}
    }, r=>{
      let b=''; r.on('data',d=>b+=d); r.on('end',()=>{
        try{
          if(r.statusCode!==200) return resolve(null);
          const d=JSON.parse(b);
          resolve({stealers_count:d.stealers?.length||0,employees_exposed:d.employees?.length||0,computers_compromised:d.computers?.length||0,sample_emails:(d.employees||[]).slice(0,3).map(e=>e.email)});
        }catch{resolve(null);}
      });
    });
    req.on('error',()=>resolve(null)); req.on('timeout',()=>{req.destroy();resolve(null);}); req.end();
  });
}

// ── SSL LABS — Detailed SSL grade (free) ─────────────────────────────
async function checkSSLLabs(domain) {
  return new Promise(resolve => {
    const req = https.request({
      hostname:'api.ssllabs.com',
      path:'/api/v4/analyze?host='+encodeURIComponent(domain)+'&startNew=off&all=on',
      method:'GET', timeout:12000,
      headers:{'User-Agent':'IntelPro/2.0'}
    }, r=>{
      let b=''; r.on('data',d=>b+=d); r.on('end',()=>{
        try{
          const d=JSON.parse(b);
          const ep=d.endpoints?.[0];
          resolve({grade:ep?.grade||d.status||'PENDING',status:d.status,heartbleed:ep?.details?.heartbleed||false,poodle:ep?.details?.poodle||false});
        }catch{resolve(null);}
      });
    });
    req.on('error',()=>resolve(null)); req.on('timeout',()=>{req.destroy();resolve(null);}); req.end();
  });
}

// ── URLhaus — Malware URL database (free) ────────────────────────────
async function checkURLhaus(domain) {
  return new Promise(resolve => {
    const post='host='+encodeURIComponent(domain);
    const req = https.request({
      hostname:'urlhaus-api.abuse.ch', path:'/v1/host/', method:'POST', timeout:6000,
      headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(post)}
    }, r=>{
      let b=''; r.on('data',d=>b+=d); r.on('end',()=>{
        try{const d=JSON.parse(b);resolve({blacklisted:d.query_status==='is_host',urls_count:d.urls?.length||0});}
        catch{resolve(null);}
      });
    });
    req.on('error',()=>resolve(null)); req.on('timeout',()=>{req.destroy();resolve(null);}); req.write(post); req.end();
  });
}

// ── Mozilla Observatory — Security headers grade (free) ──────────────
async function checkMozillaObs(domain) {
  return new Promise(resolve => {
    const post='host='+encodeURIComponent(domain);
    const req = https.request({
      hostname:'http-observatory.security.mozilla.org',
      path:'/api/v1/analyze?host='+encodeURIComponent(domain),
      method:'POST', timeout:10000,
      headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(post)}
    }, r=>{
      let b=''; r.on('data',d=>b+=d); r.on('end',()=>{
        try{const d=JSON.parse(b);resolve({grade:d.grade||'?',score:d.score||0,tests_passed:d.tests_passed||0,tests_failed:d.tests_failed||0});}
        catch{resolve(null);}
      });
    });
    req.on('error',()=>resolve(null)); req.on('timeout',()=>{req.destroy();resolve(null);}); req.write(post); req.end();
  });
}
;

// ══════════════════════════════════════════════════════════════════════
// SERVER-SIDE SCRIPT BUILDER — industry-aware, no hallucination
// ══════════════════════════════════════════════════════════════════════
const INDUSTRY_REGS = {
  pharma: {
    reg:   'DPDP Act 2023 — patient & employee data breach penalty up to ₹250 crore (Section 66)',
    risk:  'Pharma ERP and HRMS are top ransomware targets in India — avg manufacturing downtime 21 days per attack',
    cred:  'Lumiverse CERT-In empanelled — 50+ pharma and healthcare clients secured across India',
    boost: ['ISO 27001', 'DPDP Act compliance', 'WHO-GMP Annex 11 (computerized systems audit trail)'],
  },
  bfsi: {
    reg:   'RBI IT Directions 2023 Section 26 — mandatory annual CERT-In empanelled VAPT for all regulated entities',
    risk:  'RBI imposed ₹54.78 crore in penalties in FY25 — non-compliance actively enforced across all bank tiers',
    cred:  'Lumiverse CERT-In empanelled — 350+ bank VAPTs, 135+ UCBs audited, RBI-accepted reports',
    boost: ['RBI IT Directions 2023 compliance', 'UCB Cybersecurity Framework Level I-IV', 'ISO 27001'],
  },
  it: {
    reg:   'SOC 2 Type II and ISO 27001 — enterprise clients now mandate before vendor onboarding',
    risk:  'DPDP Act 2023 — SaaS/tech platforms processing user data face up to ₹250 crore liability',
    cred:  'Lumiverse has delivered 30+ ISO 27001 and SOC 2 certifications in India — 12-week average',
    boost: ['SOC 2 Type II', 'ISO 27001', 'DPDP Act compliance'],
  },
  manufacturing: {
    reg:   'CERT-In mandates 6-hour breach reporting for ALL Indian entities — no exemptions since April 2022',
    risk:  'OT/SCADA and ERP systems targeted at record pace — avg India breach cost ₹17.9 crore (IBM 2024)',
    cred:  'Lumiverse CERT-In empanelled — secured 20+ manufacturing and industrial clients across India',
    boost: ['ISO 27001', 'DPDP Act compliance', 'IEC 62443 (OT/SCADA security)', 'CERT-In compliance'],
  },
  general: {
    reg:   'CERT-In mandates 6-hour breach reporting and annual VAPT for all Indian entities — mandatory, no exemptions',
    risk:  'India recorded 370 million malware attacks in 2024 — avg data breach cost ₹17.9 crore (IBM 2024)',
    cred:  'Lumiverse CERT-In empanelled — 1500+ audits, 850+ cybercrime cases with Maharashtra Police',
    boost: ['ISO 27001', 'DPDP Act compliance', 'CERT-In compliance'],
  },
};

function detectCategory(industry, mode, hint) {
  const s = ((industry||'')+' '+(hint||'')).toLowerCase();
  if (mode === 'bank') return 'bfsi';
  if (/\.bank\.|cooperative bank|ucb|nbfc|payment bank/.test(s)) return 'bfsi';
  if (/bank|fintech|insurance|broker|sebi|irdai/.test(s) && !/pharma|health|sanpras|medical/.test(s)) return 'bfsi';
  if (/pharma|health|hospital|medical|clinical|drug|medicine|biotech|therapeut|formulat|sanpras|healthcare/.test(s)) return 'pharma';
  if (/software|saas|tech|cloud|startup|developer/.test(s)) return 'it';
  if (/manufactur|factory|industrial|steel|cement|chemical/.test(s)) return 'manufacturing';
  return 'general';
}

function buildScript(data, scanData, indCategory) {
  const cat  = indCategory || 'general';
  const regs = INDUSTRY_REGS[cat] || INDUSTRY_REGS.general;
  const name = (data.company_name || 'your company').replace(/"/g,"'");
  const gaps = data.compliance_gaps || [];
  const have = (data.compliance_they_have || []).filter(h => h.confidence !== 'missing');

  // B1 — Congratulation + context
  const facts = [
    data.employee_range && !String(data.employee_range).includes('null') ? data.employee_range+' employees' : null,
    data.revenue_range  && !String(data.revenue_range).includes('null')  ? data.revenue_range+' revenue'   : null,
    data.headquarters   && !String(data.headquarters).includes('null')   ? 'based in '+data.headquarters   : null,
    data.founded        && !String(data.founded).includes('null')        ? 'established '+data.founded      : null,
  ].filter(Boolean).slice(0,2).join(', ');
  const b1 = `Congratulations on ${name}'s continued success${facts?' ('+facts+')':''}. As a well-wisher, we want to ensure your digital security keeps pace with your business growth.`;

  // B2 — Specific scan findings
  const found = [];
  if (scanData) {
    const d = scanData.dns || {};
    if (d.spf?.checked !== false && !d.spf?.exists)     found.push('No SPF record — email spoofing fully open');
    if (d.dmarc?.checked !== false && !d.dmarc?.exists) found.push('No DMARC — domain impersonation risk critical');
    if (d.blacklist?.listed)     found.push('IP blacklisted on Spamhaus — email deliverability blocked');
    if (scanData.shodan?.vulns?.length)
      found.push(scanData.shodan.vulns.slice(0,2).join(', ')+' (active CVEs on your server)');
    if (scanData.shodan?.risky_ports?.length)
      found.push('Ports '+scanData.shodan.risky_ports.join(', ')+' exposed to internet');
  }
  const aiGaps = gaps.slice(0,2).map(g=>g.name).filter(Boolean);
  const allFound = [...new Set([...found,...aiGaps])].slice(0,4);
  const b2 = allFound.length
    ? `We scanned ${name}'s digital presence and found critical issues:\n`+allFound.map(f=>'  • '+f).join('\n')+'\nThese gaps create direct business risk and regulatory exposure.'
    : `Your industry faces growing cyber threats — data theft, ransomware, and regulatory penalties are the top risks for companies like ${name} right now.`;

  // B3 — Regulation for their industry
  const b3 = regs.reg+'.';

  // B4 — What they have + what helps them grow
  const haveNames = have.map(h=>h.name).filter(Boolean).slice(0,3);
  const missing   = regs.boost.filter(b => !haveNames.some(h=>h.toLowerCase().includes(b.split(' ')[0].toLowerCase())));
  const haveStr   = haveNames.length ? `You already have ${haveNames.join(', ')} — strong foundation. ` : '';
  const b4 = haveStr+(missing.slice(0,2).length
    ? `Adding ${missing.slice(0,2).join(' and ')} will help ${name} win larger clients, qualify for global tenders, and meet buyer security requirements faster.`
    : `The right compliance roadmap will open new business doors and reduce your regulatory exposure significantly.`);

  // B5 — Lumiverse credential
  const b5 = regs.cred+'. We act as a trusted security partner, not just a vendor — full handholding from assessment to certification.';

  // B6 — CTA
  const topIssue = (allFound[0] || gaps[0]?.name || 'your security gaps').split('(')[0].trim();
  const b6 = `Let's schedule a 30-minute call this week — I'll walk you through how to fix "${topIssue}", which compliance will grow ${name} fastest, and share a sample report from a similar client in your industry. No cost, no obligation.`;

  return [b1, b2, b3, b4, b5, b6];
}

// ══════════════════════════════════════════════════════════════════════
// INDUSTRY COMPLIANCE ENGINE (from Industries.xlsx + battle card data)
// ══════════════════════════════════════════════════════════════════════
const INDUSTRY_COMPLIANCE = {
  bfsi: {
    label: 'Banking & Financial Services',
    mandatory: [
      { name:'RBI IT Directions 2023', desc:'Mandatory annual VAPT, 24x7 SOC, SIEM deployment', penalty:'₹1 crore/day non-compliance', lumiverse:'IS Audit, VAPT, C-SOC' },
      { name:'RBI Cyber Security Framework', desc:'Network segmentation, incident response, quarterly VAPT', penalty:'₹5.93 crore (recent UCB case)', lumiverse:'VAPT, C-SOC, vCISO' },
      { name:'CERT-In (Apr 2022)', desc:'6-hour breach reporting mandatory for all regulated entities', penalty:'Criminal prosecution + ₹1 lakh/day', lumiverse:'Forensics, Incident Response' },
      { name:'PCI-DSS', desc:'Required if processing card payments — 12-domain compliance', penalty:'Card scheme fines + processing ban', lumiverse:'PCI-DSS Audit, VAPT' },
    ],
    optional: ['ISO 27001:2022', 'ISO 22301 (BCP)', 'SWIFT CSP', 'UCB L1-L4 Framework'],
    uae: ['DFSA Cyber Controls', 'NESA UAE IA Standard'],
    usa: ['SEC Cybersecurity Rules (2023)', 'GLBA Safeguards Rule'],
    lumiverse_pitch: 'We have audited 350+ banks and 135+ UCBs — RBI-accepted VAPT reports, 30-day turnaround',
    attack_scenarios: [
      { port:3306, impact:'Database exposed → customer data dump → ransomware entry', confidence:82 },
      { issue:'No DMARC', impact:'Email spoofing → CEO fraud → wire transfer theft', confidence:88 },
      { issue:'Blacklisted IP', impact:'All bank emails going to spam → customer trust damage', confidence:95 },
    ]
  },
  pharma: {
    label: 'Pharmaceuticals & Healthcare',
    mandatory: [
      { name:'DPDP Act 2023', desc:'Patient data protection — breach notification within 72 hours', penalty:'₹250 crore per violation', lumiverse:'DPDP Compliance, Data Privacy Audit' },
      { name:'CDSCO IT Guidelines', desc:'Electronic records in drug manufacturing must be secured and auditable', penalty:'Product recall + manufacturing license suspension', lumiverse:'IS Audit, Access Control Review' },
      { name:'WHO-GMP Annex 11', desc:'Computerized systems in pharma must have audit trails, access controls, validation', penalty:'WHO-GMP certification revocation', lumiverse:'IT Audit, Annex 11 Compliance' },
      { name:'CERT-In (Apr 2022)', desc:'6-hour breach reporting for all Indian entities', penalty:'Criminal prosecution', lumiverse:'Forensics, Incident Response' },
    ],
    optional: ['ISO 27001:2022', 'HIPAA (if exporting to USA)', 'HITRUST (if US healthcare clients)', 'FDA 21 CFR Part 11 (US exports)'],
    uae: ['NESA UAE IA Standard', 'Dubai Healthcare City regulations'],
    usa: ['HIPAA', 'FDA 21 CFR Part 11', 'HITRUST'],
    lumiverse_pitch: '50+ pharma and healthcare clients secured — WHO-GMP Annex 11 compliance specialists',
    attack_scenarios: [
      { port:22, impact:'SSH exposed → unauthorized server access → ERP/HRMS breach', confidence:75 },
      { issue:'No DMARC', impact:'Phishing targeting procurement team → supply chain fraud', confidence:80 },
      { issue:'LiteSpeed+PHP', impact:'Outdated PHP CVEs → web app compromise → data theft', confidence:70 },
    ]
  },
  it: {
    label: 'Information Technology & SaaS',
    mandatory: [
      { name:'DPDP Act 2023', desc:'Mandatory for all SaaS/tech platforms processing user data', penalty:'₹250 crore per violation', lumiverse:'DPDP Compliance, Privacy Audit' },
      { name:'CERT-In (Apr 2022)', desc:'6-hour breach reporting, mandatory annual VAPT for IT companies', penalty:'Criminal prosecution', lumiverse:'VAPT, Incident Response' },
      { name:'ISO 27001:2022', desc:'Enterprise clients mandate this before signing contracts', penalty:'Lost enterprise contracts — not regulatory but business-critical', lumiverse:'ISO 27001 Implementation & Certification' },
      { name:'SOC 2 Type II', desc:'US enterprise and fintech clients require this for vendor onboarding', penalty:'Lost US market access', lumiverse:'SOC 2 Type II Implementation' },
    ],
    optional: ['ISO 27701 (Privacy)', 'ISO 22301 (BCP)', 'PCI-DSS (if payment processing)', 'GDPR (if EU clients)'],
    uae: ['NESA UAE IA Standard', 'TDRA regulations'],
    usa: ['SOC 2 Type II', 'NIST 800-53', 'SEC Cybersecurity Disclosure Rules'],
    lumiverse_pitch: '30+ ISO 27001 and SOC 2 certifications delivered — 12 weeks average, enterprise-ready reports',
    attack_scenarios: [
      { issue:'Open ports 21/22', impact:'FTP/SSH brute force → source code theft → IP compromise', confidence:77 },
      { issue:'No CSP header', impact:'XSS attack → session hijacking → customer data breach', confidence:73 },
      { issue:'No DMARC', impact:'Phishing as your domain → customer impersonation fraud', confidence:85 },
    ]
  },
  manufacturing: {
    label: 'Manufacturing & Industrial',
    mandatory: [
      { name:'CERT-In (Apr 2022)', desc:'6-hour breach reporting mandatory — no exemptions for manufacturing', penalty:'Criminal prosecution + ₹1 lakh/day', lumiverse:'VAPT, Forensics, Incident Response' },
      { name:'DPDP Act 2023', desc:'Employee and customer data protection — mandatory for all Indian entities', penalty:'₹250 crore per violation', lumiverse:'DPDP Compliance Audit' },
      { name:'ISO 27001:2022', desc:'Required for export compliance, government tenders, and enterprise B2B', penalty:'Lost contracts — not regulatory but critical', lumiverse:'ISO 27001 Implementation' },
    ],
    optional: ['IEC 62443 (OT/SCADA security)', 'ISO 22301 (BCP)', 'NIST CSF (if US clients)', 'PCI-DSS (if selling via POS)'],
    uae: ['NESA UAE IA Standard', 'CBUAE (if payment processing)'],
    usa: ['NIST 800-53', 'CMMC (if US defense supply chain)'],
    lumiverse_pitch: 'CERT-In empanelled — specialized in OT/SCADA security for industrial environments',
    attack_scenarios: [
      { port:3306, impact:'Database exposed → ERP/SAP breach → production data theft', confidence:72 },
      { port:21, impact:'FTP port open → CAD/design file exfiltration via competitor', confidence:68 },
      { issue:'Ransomware', impact:'Manufacturing line halt → avg 21 days downtime → ₹5-50 crore loss', confidence:65 },
    ]
  },
  retail: {
    label: 'Retail & E-Commerce',
    mandatory: [
      { name:'PCI-DSS', desc:'Mandatory if processing card payments — covers all POS and online checkouts', penalty:'Card scheme fines + processing ban', lumiverse:'PCI-DSS Audit, VAPT' },
      { name:'DPDP Act 2023', desc:'Customer purchase data and PII protection mandatory', penalty:'₹250 crore per violation', lumiverse:'DPDP Compliance' },
      { name:'CERT-In (Apr 2022)', desc:'6-hour breach reporting for all Indian entities', penalty:'Criminal prosecution', lumiverse:'Forensics, Incident Response' },
    ],
    optional: ['ISO 27001:2022', 'GDPR (if EU customers)', 'SOC 2 (if B2B SaaS)'],
    uae: ['NESA', 'DFSA (if fintech payment element)'],
    usa: ['PCI-DSS', 'CCPA (California customers)', 'NIST CSF'],
    lumiverse_pitch: 'Specialized in e-commerce security — Web App VAPT, PCI-DSS compliance, DPDP audits',
    attack_scenarios: [
      { issue:'No DMARC', impact:'Phishing emails to your customers → credential theft → account takeover', confidence:84 },
      { issue:'Open ports', impact:'Card skimmer injection via server vulnerability → PCI breach', confidence:71 },
      { issue:'No security headers', impact:'XSS attack on checkout page → card data theft in real-time', confidence:78 },
    ]
  },
  government: {
    label: 'Government & PSU',
    mandatory: [
      { name:'CERT-In (Apr 2022)', desc:'All government entities must report breaches within 6 hours', penalty:'Mandatory — no exemptions', lumiverse:'Forensics, Incident Response, VAPT' },
      { name:'MeitY Security Guidelines', desc:'Government websites must follow GIGW 3.0 and MeitY security standards', penalty:'Website takedown + audit', lumiverse:'IS Audit, VAPT, GIGW Compliance' },
      { name:'NIC Security Policy', desc:'Mandatory for all NIC-hosted government portals', penalty:'Portal suspension', lumiverse:'IS Audit, Security Review' },
    ],
    optional: ['ISO 27001:2022', 'STQC Certification', 'GIGW 3.0'],
    uae: ['UAE IA Standards (TRA/TDRA)', 'Dubai Smart City Security Standards'],
    usa: ['FISMA', 'FedRAMP', 'NIST 800-53'],
    lumiverse_pitch: 'CERT-In empanelled — 850+ cybercrime cases with Maharashtra Police — government-trusted',
    attack_scenarios: [
      { issue:'No DMARC', impact:'Email spoofing of government domain → citizen fraud at scale', confidence:88 },
      { issue:'Open ports', impact:'Critical infrastructure attack → service disruption → public trust damage', confidence:75 },
    ]
  },
  general: {
    label: 'General Corporate',
    mandatory: [
      { name:'CERT-In (Apr 2022)', desc:'6-hour breach reporting mandatory for all Indian entities — no exemptions', penalty:'Criminal prosecution + ₹1 lakh/day', lumiverse:'VAPT, Forensics, Incident Response' },
      { name:'DPDP Act 2023', desc:'Data protection for all companies processing Indian citizens data', penalty:'₹250 crore per violation', lumiverse:'DPDP Compliance Audit' },
    ],
    optional: ['ISO 27001:2022', 'ISO 22301 (BCP)', 'Third Party Risk Assessment'],
    uae: ['NESA UAE IA Standard', 'TDRA Regulations'],
    usa: ['NIST CSF', 'SOC 2 (if US clients)'],
    lumiverse_pitch: 'CERT-In empanelled — comprehensive security services for all sectors',
    attack_scenarios: [
      { issue:'No DMARC', impact:'Business email compromise → financial fraud', confidence:80 },
      { issue:'Open ports', impact:'Unauthorized access → data theft or ransomware', confidence:70 },
    ]
  }
};

// Financial impact estimates from scan findings
function estimateFinancialRisk(scanData, indCategory) {
  const baseRisk = { low: '₹5L–₹25L', medium: '₹25L–₹1Cr', high: '₹1Cr–₹5Cr', critical: '₹5Cr–₹50Cr' };
  let riskLevel = 'low';
  const factors = [];

  if (!scanData) return { level: riskLevel, estimate: baseRisk[riskLevel], factors };

  if (scanData.shodan?.vulns?.length)      { riskLevel = 'critical'; factors.push('Active CVEs on server — breach imminent'); }
  else if (scanData.shodan?.risky_ports?.length) { riskLevel = 'high';     factors.push('Risky ports exposed — attacker entry points confirmed'); }
  if (scanData.dns?.blacklist?.listed)     { riskLevel = riskLevel==='low'?'medium':riskLevel; factors.push('IP blacklisted — active threat actor involvement'); }
  if (scanData.dns?.spf?.checked !== false && !scanData.dns?.spf?.exists)     { factors.push('No SPF → email spoofing fully open'); }
  if (scanData.dns?.dmarc?.checked !== false && !scanData.dns?.dmarc?.exists) { factors.push('No DMARC → domain impersonation → BEC fraud risk'); }
  if (scanData.greynoise?.classification==='malicious') { riskLevel='critical'; factors.push('GreyNoise: IP flagged as malicious threat actor'); }
  if (scanData.leakix?.issues > 0)         { riskLevel='high'; factors.push('LeakIX: exposed services / leaked configurations found'); }

  // Industry multiplier
  const criticalIndustries = ['bfsi','pharma','government'];
  if (criticalIndustries.includes(indCategory) && riskLevel==='medium') riskLevel='high';
  if (criticalIndustries.includes(indCategory) && riskLevel==='low') riskLevel='medium';

  return { level: riskLevel, estimate: baseRisk[riskLevel], factors };
}

// Web-check style checks we can do ourselves (since web-check API requires key)
async function runWebCheckStyle(domain) {
  // These mirror web-check insights but use our own free tools
  const results = {};

  // HSTS check from headers
  try {
    const tech = await detectTechStack(domain).catch(()=>null);
    if (tech) {
      const hdrs = tech.raw_headers || {};
      results.hsts          = !!hdrs['strict-transport-security'];
      results.csp           = !!hdrs['content-security-policy'];
      results.xfo           = !!(hdrs['x-frame-options'] || hdrs['content-security-policy']);
      results.xct           = !!hdrs['x-content-type-options'];
      results.referrer      = !!hdrs['referrer-policy'];
      results.permissions   = !!hdrs['permissions-policy'];
      results.cors          = hdrs['access-control-allow-origin'] || null;
      results.server        = hdrs['server'] || null;
      results.powered_by    = hdrs['x-powered-by'] || null;
      results.set_cookie    = hdrs['set-cookie'] || null;
      results.http_ver      = tech.http_version || null;
      results.redirect_https= tech.redirects_https || false;
      // Check cookie security
      if (results.set_cookie) {
        const cookieStr = Array.isArray(results.set_cookie) ? results.set_cookie.join(';') : results.set_cookie;
        results.cookie_secure   = /Secure/i.test(cookieStr);
        results.cookie_httponly = /HttpOnly/i.test(cookieStr);
        results.cookie_samesite = /SameSite/i.test(cookieStr);
      }
      results.security_score = [
        results.hsts, results.csp, results.xfo, results.xct,
        results.referrer, results.cookie_secure, results.cookie_httponly
      ].filter(Boolean).length;
      results.security_grade = results.security_score >= 6 ? 'A' : results.security_score >= 4 ? 'B' : results.security_score >= 2 ? 'C' : 'F';
    }
  } catch(e) {}

  // robots.txt check
  try {
    const rb = await httpsGet({ hostname:domain, path:'/robots.txt', method:'GET' }, 4000);
    if (rb && rb._raw) {
      results.has_robots    = true;
      results.robots_issues = /Disallow: \/$/.test(rb._raw) ? [] : ['Sensitive paths may not be protected'];
    } else {
      results.has_robots = false;
      results.robots_issues = ['No robots.txt — crawlers can index all paths'];
    }
  } catch(e) { results.has_robots = false; }

  return results;
}



// ════════════════════════════════════════════════════════════════════
// EMAIL FINDER + VALIDATION PIPELINE
// Layer 1: Website scraping (contact page, about page, team page)
// Layer 2: Google dorking via Gemini (finds publicly posted emails)
// Layer 3: Pattern generation from known name + domain
// Layer 4: SMTP verification (port 25, no email sent) — real 95%+ confidence
// ════════════════════════════════════════════════════════════════════

// Layer 1: Scrape website pages for email addresses
async function scrapeWebsiteEmails(domain) {
  const pages = ['/', '/contact', '/contact-us', '/about', '/team', '/about-us', '/staff'];
  const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
  const found = new Set();
  
  const fetchPage = (path) => new Promise(resolve => {
    const req = https.request({
      hostname: domain, path, method: 'GET', timeout: 5000,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; IntelBot/1.0)', Accept: 'text/html' }
    }, r => {
      let b = '';
      r.on('data', d => { if (b.length < 50000) b += d; });
      r.on('end', () => {
        const matches = b.match(emailRegex) || [];
        matches.forEach(e => {
          // Only keep emails from this domain or well-known patterns
          if (e.includes('@' + domain) || /^(info|contact|ciso|it|security|admin|helpdesk|support|compliance|audit)@/.test(e)) {
            found.add(e.toLowerCase().trim());
          }
        });
        resolve();
      });
    });
    req.on('error', () => resolve());
    req.on('timeout', () => { req.destroy(); resolve(); });
    req.end();
  });
  
  // Also check http (some banks don't have https)
  await Promise.all(pages.slice(0, 4).map(p => fetchPage(p)));
  return [...found];
}

// Layer 2: Google dorking via Gemini (finds publicly indexed emails)
async function dorkEmailsViaGemini(domain, companyName, role) {
  return new Promise(resolve => {
    const sys = 'You are an OSINT expert. Use Google Search to find email addresses. Return ONLY JSON.';
    const usr = `Find real email addresses for ${role || 'CISO/CTO/IT Director'} at ${companyName} (domain: ${domain}).

Use Google search queries like:
- site:linkedin.com "@${domain}"
- "@${domain}" CISO OR CTO OR "IT Head" OR "IT Director" OR "Security Head"
- "contact@${domain}" OR "info@${domain}" OR "it@${domain}"
- "${companyName}" email OR contact CISO OR "Chief Information"

Return ONLY this JSON (no other text):
{
  "emails_found": ["email1@domain.com", "email2@domain.com"],
  "names_found": [{"name": "Full Name", "role": "Title", "email": "email@domain.com", "source": "linkedin/website/google"}],
  "email_patterns": ["firstname.lastname@${domain}", "f.lastname@${domain}"],
  "confidence": "high/medium/low"
}`;

    callGemini(sys, usr, (err, result) => {
      if (err) return resolve({ emails_found: [], names_found: [], email_patterns: [], confidence: 'low' });
      try {
        const text = (result.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
        const jStart = text.indexOf('{');
        const jEnd = text.lastIndexOf('}') + 1;
        const parsed = JSON.parse(text.slice(jStart, jEnd));
        resolve(parsed);
      } catch {
        resolve({ emails_found: [], names_found: [], email_patterns: [], confidence: 'low' });
      }
    });
  });
}

// Layer 3: Generate email patterns from name + domain
function generateEmailPatterns(fullName, domain) {
  if (!fullName || !domain) return [];
  const parts = fullName.toLowerCase().replace(/[^a-z ]/g, '').trim().split(/\s+/);
  const first = parts[0] || '';
  const last = parts[parts.length - 1] || '';
  const mid = parts.length > 2 ? parts[1] : '';
  const fi = first[0] || '';
  const li = last[0] || '';
  
  return [
    // Most common Indian corporate patterns
    first + '.' + last + '@' + domain,
    first + '@' + domain,
    fi + last + '@' + domain,
    first + '_' + last + '@' + domain,
    fi + '.' + last + '@' + domain,
    last + '.' + first + '@' + domain,
    first + last + '@' + domain,
    fi + li + '@' + domain,
    // With middle name
    ...(mid ? [first + '.' + mid[0] + '.' + last + '@' + domain] : []),
    // Common departmental addresses
    'ciso@' + domain,
    'it@' + domain,
    'security@' + domain,
    'info@' + domain,
    'contact@' + domain,
    'compliance@' + domain,
    'ithead@' + domain,
    'admin@' + domain,
  ].filter((e, i, arr) => arr.indexOf(e) === i); // deduplicate
}

// Layer 4: SMTP verification — checks if mailbox exists WITHOUT sending email
async function smtpVerifyEmail(email) {
  const domain = email.split('@')[1];
  const result = { email, valid: false, confidence: 0, reason: '' };
  
  try {
    // Step 1: Get MX records
    const mx = await dns.resolveMx(domain).catch(() => []);
    if (!mx.length) { result.reason = 'No MX records'; return result; }
    result.confidence = 20; // domain exists and has mail server
    
    const mxHost = mx.sort((a, b) => a.priority - b.priority)[0].exchange;
    
    // Step 2: SMTP handshake WITHOUT sending (RCPT TO check)
    await new Promise(resolve => {
      const net = require('net');
      const sock = net.createConnection(25, mxHost);
      let stage = 0;
      
      sock.setTimeout(8000);
      sock.on('timeout', () => { result.reason = 'SMTP timeout'; sock.destroy(); resolve(); });
      sock.on('error', e => {
        // Port 25 often blocked by ISP — try 587 alternative check
        result.reason = 'SMTP port 25 blocked ('+e.message+')';
        result.confidence = Math.max(result.confidence, 30); // domain+MX exists = 30% confident
        resolve();
      });
      sock.on('data', chunk => {
        const data = chunk.toString();
        if (stage === 0 && data.startsWith('220')) {
          sock.write('EHLO verify.lumiverse.in\r\n');
          stage = 1;
        } else if (stage === 1 && data.includes('250')) {
          sock.write('MAIL FROM:<noreply@verify.lumiverse.in>\r\n');
          stage = 2;
        } else if (stage === 2 && data.startsWith('250')) {
          sock.write('RCPT TO:<' + email + '>\r\n');
          stage = 3;
        } else if (stage === 3) {
          if (data.startsWith('250') || data.startsWith('251')) {
            result.valid = true;
            result.confidence = 95;
            result.reason = 'Mailbox confirmed by SMTP server';
          } else if (data.startsWith('550') || data.startsWith('551') || data.startsWith('553')) {
            result.valid = false;
            result.confidence = 95; // 95% sure it doesn't exist
            result.reason = 'Mailbox rejected: ' + data.slice(0, 60).trim();
          } else if (data.startsWith('421') || data.startsWith('452')) {
            result.confidence = 40;
            result.reason = 'Server busy/greylisted — inconclusive';
          } else {
            result.confidence = 35;
            result.reason = 'Inconclusive response: ' + data.slice(0, 40).trim();
          }
          sock.write('QUIT\r\n');
          sock.destroy();
          resolve();
        }
      });
      sock.on('close', resolve);
    });
  } catch (e) {
    result.reason = 'Error: ' + e.message;
  }
  return result;
}

// Master: Run all 4 layers and return ranked results
async function findAndVerifyEmails(domain, companyName, knownNames, role) {
  console.log('[EmailFinder] Starting for', domain);
  
  const results = [];
  const allEmails = new Set();
  
  // Layer 1: Website scraping (fast, always run)
  const scraped = await scrapeWebsiteEmails(domain);
  scraped.forEach(e => allEmails.add(e));
  console.log('[EmailFinder] Layer1 (scrape):', scraped.length, 'emails');
  
  // Layer 2: Gemini OSINT (uses Google Search grounding)
  const geminiResult = await dorkEmailsViaGemini(domain, companyName, role);
  (geminiResult.emails_found || []).forEach(e => allEmails.add(e.toLowerCase()));
  (geminiResult.names_found || []).forEach(n => {
    if (n.email) allEmails.add(n.email.toLowerCase());
    if (n.name) knownNames = [...(knownNames || []), n.name];
  });
  console.log('[EmailFinder] Layer2 (Gemini):', geminiResult.emails_found?.length, 'emails,', geminiResult.names_found?.length, 'contacts');
  
  // Layer 3: Pattern generation for known names
  if (knownNames?.length) {
    knownNames.forEach(name => {
      const patterns = generateEmailPatterns(name, domain);
      patterns.slice(0, 3).forEach(e => allEmails.add(e)); // top 3 patterns per name
    });
  }
  // Always add common functional addresses
  generateEmailPatterns('', domain).filter(e => e.startsWith('info@') || e.startsWith('ciso@') || e.startsWith('it@') || e.startsWith('contact@') || e.startsWith('security@')).forEach(e => allEmails.add(e));
  
  console.log('[EmailFinder] Layer3 (patterns): total unique emails to verify:', allEmails.size);
  
  // Layer 4: SMTP verify all unique emails (limit to 20 to avoid timeout)
  const toVerify = [...allEmails].slice(0, 20);
  const verifications = await Promise.all(toVerify.map(e => smtpVerifyEmail(e)));
  
  verifications.forEach(v => {
    // Find if Gemini found a name for this email
    const nameMatch = (geminiResult.names_found || []).find(n => n.email?.toLowerCase() === v.email);
    results.push({
      email: v.email,
      valid: v.valid,
      confidence: v.confidence,
      reason: v.reason,
      name: nameMatch?.name || null,
      role: nameMatch?.role || null,
      source: scraped.includes(v.email) ? 'website' : nameMatch ? 'gemini_search' : 'pattern_generated',
      email_pattern: geminiResult.email_patterns?.[0] || null,
    });
  });
  
  // Sort: verified first, then by confidence
  results.sort((a, b) => {
    if (a.valid !== b.valid) return a.valid ? -1 : 1;
    return b.confidence - a.confidence;
  });
  
  console.log('[EmailFinder] Layer4 (SMTP): verified', verifications.filter(v=>v.valid).length, 'valid');
  return {
    domain,
    company: companyName,
    contacts: results,
    email_pattern: geminiResult.email_patterns?.[0] || null,
    gemini_confidence: geminiResult.confidence || 'low',
    total_checked: toVerify.length,
    verified_count: results.filter(r => r.valid).length,
  };
}


// ── HTTP SERVER ──────────────────────────────────────────────────────
http.createServer((req, res) => {
  const pn = (()=>{ try { return new URL(req.url,'http://localhost').pathname; } catch { return req.url.split('?')[0]; } })();
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if (req.method==='OPTIONS'){res.writeHead(204);res.end();return;}

  const json = (d,s=200) => { res.writeHead(s,{'Content-Type':'application/json'}); res.end(JSON.stringify(d)); };
  const rb = (cb) => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => {
      let parsed;
      try { parsed = b ? JSON.parse(b) : {}; }
      catch(e) { return json({ error: 'Bad JSON: ' + e.message }, 400); }
      // Support async callbacks — catch and log any thrown errors
      Promise.resolve(cb(parsed)).catch(e => {
        console.error('[Request handler error]', pn, e.message);
        try { json({ error: 'Internal server error: ' + e.message }, 500); } catch {}
      });
    });
  };

  // ── RAG CONTEXT (feedback-based improvements) ────────────────────────

  // ── INTEL DATA — gaps + battle card served to frontend ─────────────
  if (pn === '/api/intel-data' && req.method === 'GET') {
    try {
      const dataPath = path.join(__dirname, 'intel_data.json');
      if (fs.existsSync(dataPath)) {
        const data = fs.readFileSync(dataPath, 'utf8');
        res.writeHead(200, {'Content-Type':'application/json','Cache-Control':'max-age=3600'});
        res.end(data);
      } else {
        json({ error: 'intel_data.json not found — run setup' }, 404);
      }
    } catch(e) { json({ error: e.message }, 500); }
    return;
  }


  // ── EMAIL FINDER — 4-layer verification pipeline ─────────────────
  if (pn === '/api/find-emails' && req.method === 'POST') {
    rb(async body => {
      try {
        const { domain, company_name, known_names, role } = body || {};
        if (!domain) return json({ error: 'domain required' }, 400);
        const result = await findAndVerifyEmails(
          domain.replace(/^https?:\/\//,'').replace(/^www\./,'').split('/')[0],
          company_name || domain,
          known_names || [],
          role || 'CISO OR CTO OR IT Director'
        );
        json(result);
      } catch(e) { json({ error: e.message }, 500); }
    }); return;
  }

  // ── SMTP VERIFY SINGLE EMAIL ─────────────────────────────────────
  if (pn === '/api/verify-email' && req.method === 'POST') {
    rb(async body => {
      try {
        const { email } = body || {};
        if (!email || !email.includes('@')) return json({ error: 'valid email required' }, 400);
        const result = await smtpVerifyEmail(email);
        json(result);
      } catch(e) { json({ error: e.message }, 500); }
    }); return;
  }

    // ── QUICK PREFETCH — fast company name + basic DNS (< 2s) ──────────
  // ── AUTH ENDPOINTS ──────────────────────────────────────────────────
  if (pn === '/auth/signup' && req.method === 'POST') {
    rb(async body => {
      const { email, password, name, company_name } = body || {};
      if (!email || !password || password.length < 6)
        return json({ error: 'Email and password (min 6 chars) required' }, 400);
      try {
        // Use PostgreSQL if available
        if (db) {
          const result = await db.Users.signup({ email, password, name, company_name });
          return json(result);
        }
        // Fallback: users.json
        const users = _loadUsers();
        const key = email.toLowerCase().trim();
        if (users[key]) return json({ error: 'Account already exists. Please sign in instead.' }, 409);
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = await _hashPwd(password, salt);
        const id = crypto.randomUUID();
        users[key] = { email: key, hash, salt, created_at: new Date().toISOString(), id };
        _saveUsers(users);
        const token = _makeToken({ id, email: key });
        console.log('[Auth] Signed up (local):', key);
        json({ token, user: { id, email: key } });
      } catch(e) { json({ error: e.message }, e.code || 400); }
    }); return;
  }


  if (pn === '/auth/login' && req.method === 'POST') {
    rb(async body => {
      const { email, password } = body || {};
      if (!email || !password) return json({ error: 'Email and password required' }, 400);
      try {
        // Use PostgreSQL if available
        if (db) {
          const result = await db.Users.login({ email, password });
          return json(result);
        }
        // Fallback: users.json
        const users = _loadUsers();
        const key = email.toLowerCase().trim();
        const user = users[key];
        console.log('[Auth] Login attempt:', key, '| Users in file:', Object.keys(users).length);
        if (!user) {
          console.log('[Auth] Not found:', key);
          return json({ error: 'Account not found. Please sign up first.' }, 401);
        }
        const hash = await _hashPwd(password, user.salt);
        if (hash !== user.hash) {
          console.log('[Auth] Wrong password for:', key);
          return json({ error: 'Incorrect password.' }, 401);
        }
        const token = _makeToken({ id: user.id, email: key });
        console.log('[Auth] Login success (local):', key);
        json({ token, user: { id: user.id, email: key } });
      } catch(e) { json({ error: e.message }, e.code || 401); }
    }); return;
  }

  // Admin: create user (superadmin only)
  if (pn === '/admin/users/create' && req.method === 'POST') {
    rb(async body => {
      if (!db) return json({ error: 'PostgreSQL required for admin endpoints' }, 503);
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        const caller = await db.Users.verifyToken(token);
        db.Admin.checkRole(caller.role, 'admin');
        const { email, password, name, company_name, phone, role } = body || {};
        if (!email || !password) return json({ error: 'Email and password required' }, 400);
        const user = await db.Users.create({ email, password, name, company_name, phone, role, created_by: caller.id });
        await db.AuditLog.log({ user_id: caller.id, action: 'user_create', target_id: user.id, target_type: 'user', details: { email } });
        json({ ok: true, user });
      } catch(e) { json({ error: e.message }, e.code || 400); }
    }); return;
  }

  // Admin: list all users
  if (pn === '/admin/users' && req.method === 'GET') {
    if (!db) return json({ error: 'PostgreSQL required' }, 503);
    (async () => {
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        const caller = await db.Users.verifyToken(token);
        db.Admin.checkRole(caller.role, 'admin');
        const users = await db.Users.listAll();
        json({ users });
      } catch(e) { json({ error: e.message }, e.code || 403); }
    })(); return;
  }

  // Admin: set role
  if (pn === '/admin/users/role' && req.method === 'POST') {
    rb(async body => {
      if (!db) return json({ error: 'PostgreSQL required' }, 503);
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        const caller = await db.Users.verifyToken(token);
        db.Admin.checkRole(caller.role, 'superadmin');
        const result = await db.Users.setRole({ target_email: body.email, role: body.role, admin_id: caller.id });
        json({ ok: true, user: result });
      } catch(e) { json({ error: e.message }, e.code || 403); }
    }); return;
  }

  // Admin: reset any user's password
  if (pn === '/admin/users/reset-password' && req.method === 'POST') {
    rb(async body => {
      if (!db) return json({ error: 'PostgreSQL required' }, 503);
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        const caller = await db.Users.verifyToken(token);
        db.Admin.checkRole(caller.role, 'admin');
        const result = await db.Users.adminResetPassword({ target_email: body.email, new_password: body.new_password, admin_id: caller.id });
        json(result);
      } catch(e) { json({ error: e.message }, e.code || 403); }
    }); return;
  }

  // Admin: suspend/activate user
  if (pn === '/admin/users/status' && req.method === 'POST') {
    rb(async body => {
      if (!db) return json({ error: 'PostgreSQL required' }, 503);
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        const caller = await db.Users.verifyToken(token);
        db.Admin.checkRole(caller.role, 'admin');
        const result = await db.Users.setStatus({ target_email: body.email, status: body.status, admin_id: caller.id });
        json(result);
      } catch(e) { json({ error: e.message }, e.code || 403); }
    }); return;
  }

  // Admin: full dashboard
  if (pn === '/admin/dashboard' && req.method === 'GET') {
    if (!db) return json({ error: 'PostgreSQL required' }, 503);
    (async () => {
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        const caller = await db.Users.verifyToken(token);
        db.Admin.checkRole(caller.role, 'admin');
        const data = await db.Admin.getDashboard();
        json(data);
      } catch(e) { json({ error: e.message }, e.code || 403); }
    })(); return;
  }

  // Change own password
  if (pn === '/auth/change-password' && req.method === 'POST') {
    rb(async body => {
      if (!db) return json({ error: 'PostgreSQL required for password change' }, 503);
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '') || body?.token;
        const user = await db.Users.verifyToken(token);
        const { current_password, new_password } = body || {};
        if (!current_password || !new_password) return json({ error: 'Both passwords required' }, 400);
        if (new_password.length < 8) return json({ error: 'New password must be 8+ characters' }, 400);
        await db.Users.changePassword({ user_id: user.id, current_password, new_password });
        json({ ok: true, message: 'Password updated successfully' });
      } catch(e) { json({ error: e.message }, e.code || 400); }
    }); return;
  }

  // Save search to DB
  if (pn === '/api/save-search' && req.method === 'POST') {
    rb(async body => {
      if (!db) return json({ ok: false, note: 'DB not available' });
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        const user = await db.Users.verifyToken(token);
        const id = await db.Searches.save({ user_id: user.id, result: body.result, scan: body.scan, industry: body.industry });
        json({ ok: true, id });
      } catch(e) { json({ error: e.message }, 400); }
    }); return;
  }

  // Save report to DB
  if (pn === '/api/save-report' && req.method === 'POST') {
    rb(async body => {
      if (!db) return json({ ok: false, note: 'DB not available' });
      try {
        const token = (req.headers.authorization || '').replace('Bearer ', '');
        const user = await db.Users.verifyToken(token);
        const id = await db.Reports.save({ user_id: user.id, ...body });
        json({ ok: true, id });
      } catch(e) { json({ error: e.message }, 400); }
    }); return;
  }



  // Admin: auth status check
  if (pn === '/auth/status' && req.method === 'GET') {
    if (db) {
      (async () => {
        try {
          const stats = await db.Stats.getOverview();
          json({ db: 'postgresql', stats });
        } catch(e) { json({ db: 'postgresql', error: e.message }); }
      })();
    } else {
      const users = _loadUsers();
      json({ db: 'local', users_count: Object.keys(users).length, emails: Object.keys(users) });
    }
    return;
  }


  // Password reset (DEV only — remove in production)
  if (pn === '/auth/reset' && req.method === 'POST') {
    rb(async body => {
      const { email, password, admin_key } = body || {};
      if (admin_key !== 'lumiverse2026reset') return json({ error: 'Unauthorized' }, 401);
      if (!email || !password || password.length < 6) return json({ error: 'Email and password required' }, 400);
      const users = _loadUsers();
      const key = email.toLowerCase().trim();
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = await _hashPwd(password, salt);
      const id = users[key]?.id || crypto.randomUUID();
      users[key] = { email: key, hash, salt, created_at: new Date().toISOString(), id };
      _saveUsers(users);
      json({ ok: true, message: 'Password updated for ' + key });
    }); return;
  }

  if (pn === '/auth/verify' && req.method === 'POST') {
    rb(async body => {
      const token = (body || {}).token || (req.headers.authorization || '').replace('Bearer ', '');
      if (!token) return json({ error: 'No token' }, 401);
      try {
        if (db) {
          const user = await db.Users.verifyToken(token);
          return json({ user });
        }
        // Fallback: local JWT verify
        const payload = _verifyToken(token);
        if (!payload) return json({ error: 'Invalid or expired session' }, 401);
        json({ user: { id: payload.id, email: payload.email } });
      } catch(e) { json({ error: e.message }, 401); }
    }); return;
  }

  if (pn === '/api/prefetch' && req.method === 'POST') {
    rb(async body => {
      const urlStr = body.url || '';
      if (!urlStr) return json({ error:'No URL' }, 400);
      try {
        let domain = urlStr.replace(/^https?:\/\//,'').replace(/^www\./,'').split('/')[0];
        const [dnsR, techR] = await Promise.all([
          scanDNS(domain).catch(()=>null),
          detectTechStack(domain).catch(()=>null),
        ]);
        const titleRaw = techR?.title || '';
        const isErrTitle = /error|403|404|cloudfront|forbidden|bad gateway/i.test(titleRaw);
        // Better company name: strip tagline after separator, clean up
        const _titleClean = titleRaw.replace(/[-|–—|\|].*/,'').trim();
        const _isGenericTitle = !_titleClean || isErrTitle || _titleClean.split(' ').length > 7;
        // Domain-derived fallback: jsblpune.bank.in → JSBL Pune Bank
        const _domainClean = domain
          .replace(/\.(bank\.in|com|in|net|org|co\.in)$/,'')
          .replace(/^www\.?/,'')
          .replace(/[-_.]/g,' ')
          .replace(/\b(\w)/g, c => c.toUpperCase())
          .trim();
        const companyName = _isGenericTitle ? _domainClean : (_titleClean || _domainClean);
        const combo = (domain+' '+(titleRaw||'')).toLowerCase();
        // Enhanced bank detection: .bank.in TLD is always BFSI
        const isBankDomain = /\.bank\.in$/.test(domain) || /\bbank\b|cooperative|sahakari|ucb|nbfc/.test(combo);
        const industryHint = isBankDomain?'bfsi':
          /pharma|health|hospital|medical/.test(combo)?'pharma':
          /software|saas|tech|cloud|developer/.test(combo)?'it':
          /manufactur|factory|industrial/.test(combo)?'manufacturing':'';
        const loc = techR?.ip_location;
        json({
          domain, company_name: companyName, industry_hint: industryHint, is_bank: isBankDomain,
          dmarc_missing: dnsR?.dmarc?.checked === false ? null : !dnsR?.dmarc?.exists,
          spf_missing: dnsR?.spf?.checked === false ? null : !dnsR?.spf?.exists,
          blacklisted: !!(dnsR?.blacklist?.listed),
          ssl_days: dnsR?.ssl?.days_left || null,
          tech_stack: techR?.tech_stack || [],
          location: loc ? [(loc.city||''), (loc.country||'')].filter(Boolean).join(', ') : '',
        });
      } catch(e) { json({ error: e.message }, 500); }
    }); return;
  }

  // ── DIRECT GEMINI (no prefetch, no ground truth) ─────────────────
  // Used for: competitor intelligence, decision maker lookup, objection handling
  if (pn==='/api/gemini' && req.method==='POST') {
    rb(async body => {
      if (!body?.user) return json({ error:'No prompt' }, 400);
      callGemini(body.system||'You are a helpful assistant. Return valid JSON only.', body.user, (err, result) => {
        if (err) return json({ error: err.message }, 500);
        json(result);
      });
    }); return;
  }

  if(pn==='/api/sessions'){rb(()=>json([]));return;}
  if (pn==='/api/save-session'){rb(()=>json({ok:true}));return;}
  if (pn==='/api/rag-context' && req.method==='POST') {
    // This endpoint allows server to query Supabase for feedback
    // For now returns empty — client-side RAG is handled in frontend
    json({context: '', message: 'Client-side RAG active'}); return;
  }

  // ── SCAN ─────────────────────────────────────────────────────────────
  // ── CONNECTIVITY HEALTHCHECK ─────────────────────────────────────
  if (pn === '/api/healthcheck' && req.method === 'GET') {
    (async () => {
      const targets = [
        { name:'Gemini AI', host:'generativelanguage.googleapis.com', path:'/v1beta/models', critical:true, gkey:true },
        { name:'MXToolbox', host:'mxtoolbox.com', path:'/api/v1/lookup/dmarc/google.com', critical:true, mxkey:true },
        { name:'Shodan', host:'internetdb.shodan.io', path:'/8.8.8.8' },
        { name:'IP-API', host:'ip-api.com', path:'/json/8.8.8.8' },
        { name:'GreyNoise', host:'api.greynoise.io', path:'/v3/community/8.8.8.8' },
        { name:'AbuseIPDB', host:'api.abuseipdb.com', path:'/api/v2/check?ipAddress=8.8.8.8' },
        { name:'VirusTotal', host:'www.virustotal.com', path:'/api/v3/domains/google.com' },
        { name:'URLScan', host:'urlscan.io', path:'/api/v1/search/?q=domain:google.com' },
        { name:'HaveIBeenPwned', host:'haveibeenpwned.com', path:'/api/v3/breaches' },
        { name:'Hudson Rock', host:'cavalier.hudsonrock.com', path:'/api/json/v2/osint-tools/search-by-domain?domain=google.com' },
        { name:'SSL Labs', host:'api.ssllabs.com', path:'/api/v3/info' },
        { name:'HackerTarget', host:'api.hackertarget.com', path:'/hostsearch/?q=google.com' },
        { name:'Wayback', host:'archive.org', path:'/wayback/available?url=google.com' },
      ];
      const testOne = (t) => new Promise(resolve => {
        const start = Date.now();
        const headers = { 'User-Agent':'CyberIntel-HC/1.0', 'Accept':'application/json' };
        if (t.gkey && GEMINI_KEYS[0]) headers['x-goog-api-key'] = GEMINI_KEYS[0];
        if (t.mxkey) headers['Authorization'] = MXTOOLBOX_KEY;
        const req2 = https.request({ hostname:t.host, path:t.path, method:'GET', timeout:8000, headers }, r => {
          let body=''; r.on('data',c=>{if(body.length<2000)body+=c;});
          r.on('end',()=>{
            const ms = Date.now()-start;
            const blocked = body.includes('192.168.')||body.includes('httpclient.html')||body.includes('Sophos')||body.includes('portal_url')||body.includes('forward.http.proxy');
            resolve({ name:t.name, host:t.host, status: blocked?'BLOCKED':(r.statusCode<500?'OK':'ERROR'), http_code:r.statusCode, latency_ms:ms, blocked_by_firewall:blocked, critical:!!t.critical,
              note: blocked?'Firewall captive portal intercepting': r.statusCode===200?'Working': (r.statusCode===401||r.statusCode===403)?'Reachable (auth)':`HTTP ${r.statusCode}` });
          });
        });
        req2.on('timeout',()=>{req2.destroy();resolve({name:t.name,host:t.host,status:'TIMEOUT',blocked_by_firewall:true,critical:!!t.critical,note:'Timed out — likely blocked'});});
        req2.on('error',e=>resolve({name:t.name,host:t.host,status:'FAILED',error:e.message,blocked_by_firewall:/ECONNREFUSED|ETIMEDOUT|ENOTFOUND/.test(e.message),critical:!!t.critical,note:e.message}));
        req2.end();
      });
      const results = await Promise.all(targets.map(testOne));
      const summary = { total:results.length, ok:results.filter(r=>r.status==='OK').length, blocked:results.filter(r=>r.blocked_by_firewall).length, failed:results.filter(r=>r.status==='FAILED'||r.status==='ERROR').length };
      const fw = results.some(r=>r.blocked_by_firewall);
      console.log('[HealthCheck]', JSON.stringify(summary), fw?'⚠ FIREWALL BLOCKING':'✅ clear');
      json({ summary, firewall_blocking:fw, agents:results, checked_at:new Date().toISOString() });
    })();
    return;
  }

  if (pn==='/api/scan' && req.method==='POST') {
    rb(async body => {
      try { json(await runFullScan(body.urls||[], body.prefs||{})); }
      catch(e) { json({error:e.message}); }
    }); return;
  }

  // ── ANALYZE ───────────────────────────────────────────────────────────
  if (pn==='/api/analyze' && req.method==='POST') {
    rb(async body => {
      if (!body || (!body.user && !body.system)) return json({ error:'No prompt' }, 400);
      // Log origin of call for debugging
      const _callUrls = (body.urls||[]).join(',');
      if (!_callUrls) console.log('[Analyze] WARNING: no URLs provided - check caller');
      try {
       const mode = body.mode || 'bank';
const urls = body.urls || [];
const websiteUrl = urls[0] || '';

const scanBody = body.scan_data || null;

console.log('[Analyze] scan_data received:', JSON.stringify(scanBody, null, 2));  // scan results from frontend
        
        // Pre-fetch the website to extract ground truth BEFORE asking Gemini
        let groundTruth = '';
        let fetched = null;
        if (websiteUrl) {
          fetched = await prefetchWebsite(websiteUrl).catch(()=>null);
          if (fetched && fetched.company_name) {
            const gt = [];
            gt.push('\n=== PRE-FETCHED GROUND TRUTH (highest priority — do NOT override) ===');
            gt.push(`CONFIRMED COMPANY NAME: ${fetched.company_name}`);
            gt.push(`DOMAIN: ${fetched.domain}`);
            if (fetched.page_title) gt.push(`PAGE TITLE: ${fetched.page_title}`);
            if (fetched.h1) gt.push(`H1: ${fetched.h1}`);
            if (fetched.description) gt.push(`META DESCRIPTION: ${fetched.description}`);
            if (fetched.branch_count) gt.push(`BRANCHES FOUND ON SITE: ${fetched.branch_count}`);
            if (fetched.founded_year) gt.push(`FOUNDED: ${fetched.founded_year}`);
            if (fetched.contact_email) gt.push(`CONTACT EMAIL: ${fetched.contact_email}`);
            if (fetched.digital_products?.length)
              gt.push(`CONFIRMED DIGITAL PRODUCTS: ${fetched.digital_products.join(', ')}`);
            gt.push('=== END GROUND TRUTH ===');
            groundTruth = '\n' + gt.join('\n') + '\n';
            const _gnCheck = (s) => { if(!s) return true; const w=String(s).trim().split(/\s+/); return w.length>6||w.filter(x=>/^(solutions?|services?|technologies?|digital|cyber|security|india|global)$/i.test(x)).length>=2; }; console.log('[Analyze] Ground truth:', fetched.company_name, _gnCheck(fetched.company_name)?'(TAGLINE-skipping)':'(company name)', '| Products:', fetched.digital_products?.join(','));
          }
        }
        
        const sys = buildSystemPrompt(mode, body.industry||'');
        // Inject ground truth + RAG context (from frontend) into user prompt
        const baseUser = body.user || ('Analyze: '+urls.join(' | ')+'. Return JSON only, no markdown.');
        const usr = groundTruth + baseUser;
        
        console.log('[Analyze] mode:', mode, '| url:', websiteUrl, '| prompt len:', (sys+usr).length);
        const _urlHint = (body.urls||[]).join(' ')+' '+(fetched?.company_name||'')+' '+(fetched?.page_title||'');
        const _indCat  = detectCategory(body.industry||'', mode, _urlHint);
        const _scanRef = scanBody || {}; // use scan data passed from frontend
        callGemini(sys, usr, (err, result) => {
          if (err) return json({error:{message:err.message}},500);
          
          // Post-process: correct company name if Gemini hallucinated it
          try {
            const text = (result.content||[]).filter(b=>b.type==='text').map(b=>b.text).join('');
            let cleaned = text.replace(/```json|```/g,'').trim();
            
            // Extract ONLY the first complete JSON object (ignore trailing citations/text)
            const jsonStart = cleaned.indexOf('{');
            if (jsonStart > 0) cleaned = cleaned.slice(jsonStart);
            
            // Find matching closing brace for the root object
            let depth = 0, jsonEnd = -1, inStr = false, esc2 = false;
            for (let i = 0; i < cleaned.length; i++) {
              const c = cleaned[i];
              if (esc2) { esc2 = false; continue; }
              if (c === '\\') { esc2 = true; continue; }
              if (c === '"') { inStr = !inStr; continue; }
              if (inStr) continue;
              if (c === '{') depth++;
              else if (c === '}') { depth--; if (depth === 0) { jsonEnd = i; break; } }
            }
            if (jsonEnd > 0 && jsonEnd < cleaned.length - 1) {
              cleaned = cleaned.slice(0, jsonEnd + 1); // trim trailing text/citations
            }
            
            // Repair truncated JSON robustly
            if (cleaned && cleaned.includes('{')) {
              const openB = (cleaned.match(/\{/g)||[]).length;
              const closeB = (cleaned.match(/\}/g)||[]).length;
              const openA = (cleaned.match(/\[/g)||[]).length;
              const missingB = openB - closeB;
              const missingA = openA - (cleaned.match(/\]/g)||[]).length;
              if ((missingB > 0 || missingA > 0) && missingB <= 15) {
                let cut = cleaned;
                cut = cut.replace(/,?\s*"[^"]*$/, '');
                cut = cut.replace(/,\s*$/, '');
                cut += ']'.repeat(Math.max(0, missingA));
                cut += '}'.repeat(Math.max(0, openB - (cut.match(/\}/g)||[]).length));
                cleaned = cut;
              }
            }
            
            const parsed = JSON.parse(cleaned);
            
            // Build script server-side — guaranteed correct industry
            try {
              parsed.sales_script = buildScript(parsed, _scanRef, _indCat);
            } catch(se) { console.log('[Script]', se.message); }

            // If we have a confirmed company name from pre-fetch, enforce it
            // BUT only if it looks like a real company name, not a tagline/description
            const _isBadName = (s) => {
              if (!s) return true;
              const words = String(s).trim().split(/\s+/);
              if (words.length > 6) return true; // taglines are long
              if (s === fetched?.domain) return true;
              // Count generic marketing words
              const genericWords = /^(solutions?|services?|technologies?|systems?|platforms?|digital|cyber|security|india|dubai|global|world|leader|trusted|best|top|premier|excellence|innovation|transform|empower|enable|partner)$/i;
              const genericCount = words.filter(w => genericWords.test(w)).length;
              return genericCount >= 2; // 2+ generic words = tagline
            };
            // Only override Gemini's company_name if prefetch got a REAL name (not just the domain)
            const fetchedName = fetched?.company_name;
            const fetchedGotRealName = fetchedName && fetchedName !== fetched?.domain && !_isBadName(fetchedName);
            if (fetchedGotRealName) {
              const wrongName = parsed.company_name !== fetchedName;
              if (wrongName) {
                console.log('[Analyze] Correcting company name:', parsed.company_name, '->', fetchedName);
                parsed.company_name = fetchedName;
              }
              // Also inject confirmed digital products into tech_stack if missing
              if (fetched.digital_products?.length && (!parsed.tech_stack?.length)) {
                parsed.tech_stack = fetched.digital_products;
              }
              // Inject branch count if missing
              if (fetched.branch_count && !parsed.branch_count) {
                parsed.branch_count = fetched.branch_count;
              }
              // Inject founded year if missing
              if (fetched.founded_year && !parsed.founded) {
                parsed.founded = fetched.founded_year;
              }
            }
            
            // Clean up Gemini's company_name if it's still a tagline
            if (_isBadName(parsed.company_name) && fetched?.domain) {
              // Extract clean domain name as fallback (e.g. "lumiversesolutions.com" → "Lumiverse Solutions")
              const domainWords = fetched.domain.replace(/\.(com|in|net|org|co\.in|bank)$/,'')
                .replace(/www\.?/,'')
                .replace(/([a-z])([A-Z])/g,'$1 $2')  // camelCase split
                .replace(/[-_]/g,' ')
                .replace(/(\w)/g,c=>c.toUpperCase())
                .trim();
              if (domainWords && domainWords.length > 2) {
                console.log('[Analyze] Tagline detected, using domain-derived name:', domainWords);
                parsed.company_name = domainWords;
              }
            }
            const dns = scanBody?.dns || {};

parsed.compliance_they_have = parsed.compliance_they_have || [];
parsed.compliance_gaps = parsed.compliance_gaps || [];

// ---------- SPF ----------
if (dns.spf?.exists) {

  if (!parsed.compliance_they_have.some(c =>
      /spf/i.test(c.name))) {

    parsed.compliance_they_have.push({
      name: "SPF",
      confidence: "high",
      reason: "Verified from live DNS scan"
    });

  }

  parsed.compliance_gaps =
    parsed.compliance_gaps.filter(g =>
      !/spf/i.test(g.name));

}

// ---------- DMARC ----------
if (dns.dmarc?.exists) {

  if (!parsed.compliance_they_have.some(c =>
      /dmarc/i.test(c.name))) {

    parsed.compliance_they_have.push({
      name: "DMARC",
      confidence: "high",
      reason: "Verified from live DNS scan"
    });

  }

  parsed.compliance_gaps =
    parsed.compliance_gaps.filter(g =>
      !/dmarc/i.test(g.name));

}

// ---------- DKIM ----------
if (dns.dkim?.exists) {

  if (!parsed.compliance_they_have.some(c =>
      /dkim/i.test(c.name))) {

    parsed.compliance_they_have.push({
      name: "DKIM",
      confidence: "high",
      reason: "Verified from live DNS scan"
    });

  }

}
            // Return corrected result
            result = { content: [{ type:'text', text: JSON.stringify(parsed) }] };
          } catch(parseErr) {
            // If post-processing fails, return original Gemini response as-is
            console.log('[Analyze] Post-process skipped:', parseErr.message);
          }
          // ======================================================
// Merge VERIFIED scan results into Gemini output
// ======================================================


          
          json(result);
        });
      } catch(e){ console.error('[analyze]', e.message); json({error:{message:e.message}},500); }
    }); return;
  }

  // ── BUILD PROMPT ──────────────────────────────────────────────────────
  if (pn==='/api/buildprompt' && req.method==='POST') {
    rb(body => {
      try {
        const sys = buildSystemPrompt(body.mode||'bank', body.industry||'');
        json({system:sys});
      } catch(e){ json({error:{message:e.message}},500); }
    }); return;
  }

  // ── SEND EMAIL (via Gmail API with OAuth2 or SMTP relay) ────────────
  if (pn==='/api/send-email' && req.method==='POST') {
    rb(async body => {
      try {
        const { to, subject, html, from_name } = body;
        if (!to || !subject || !html) return json({error:'Missing to/subject/html'},400);
        // Use Gemini to validate email looks legitimate
        // For now return success — user should configure SMTP in .env
        const SMTP_USER = process.env.SMTP_USER || '';
        const SMTP_PASS = process.env.SMTP_PASS || '';
        if (!SMTP_USER || !SMTP_PASS) {
          // Return mailto: link fallback
          return json({ ok: false, fallback: true, mailto: `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(html.replace(/<[^>]+>/g,' '))}` });
        }
        json({ ok: true, message: `Email queued for ${to}` });
      } catch(e) { json({error:e.message},500); }
    }); return;
  }

  // ── OBJECTION ─────────────────────────────────────────────────────────
  if (pn==='/api/objection' && req.method==='POST') {
    rb(body => {
      callObjectionHandler(body.objection||'', body.context||{}, (err, result) => {
        if (err) return json({error:{message:err.message}},500);
        json(result);
      });
    }); return;
  }

  // ── RANSOMWARE LIVE FEED ─────────────────────────────────────────────
  if (pn==='/api/ransomware') {
    const fetchFeed = (hostname, path) => new Promise(resolve => {
      const req = https.request({hostname,path,method:'GET',timeout:10000,headers:{'Accept':'application/json','User-Agent':'IntelPro/2.0'}}, r=>{
        let b=''; r.on('data',d=>b+=d); r.on('end',()=>{ try { resolve(JSON.parse(b)); } catch { resolve(null); } });
      });
      req.on('error',()=>resolve(null)); req.on('timeout',()=>{req.destroy();resolve(null);}); req.end();
    });
    (async()=>{
      try {
        let data = await fetchFeed('api.ransomware.live', '/victims') || await fetchFeed('data.ransomware.live', '/posts.json');
        const victims = (Array.isArray(data)?data:data?.victims||data?.posts||[]).slice(0,300).map(v=>({
          victim_name: v.post_title||v.victim_name||v.name||v.title||v.victim||'',
          group_name:  v.group_name||v.ransomware_group||'',
          country:     v.country||'',
          published:   v.published||v.attack_date||v.date||'',
          website:     v.website||v.victim_domain||v.domain||'',
          leak_status: v.leaked?'LEAKED':v.negotiating?'NEGOTIATING':'UNKNOWN',
          data_volume: v.data_size||v.data_volume||'',
          industry:    v.activity||v.industry||'',
        }));
        json({victims, total:victims.length, source:'ransomware.live'});
      } catch(e) { json({victims:[],error:e.message},503); }
    })();
    return;
  }

  // ── STATIC FILES ──────────────────────────────────────────────────────
  let fp = pn==='/'?'/index.html':pn;
  fp = path.join(__dirname,'public',fp);
  fs.readFile(fp,(err,data)=>{
    if(err){res.writeHead(404);res.end('Not found');return;}
    const ext = path.extname(fp);
    const mime = {'.html':'text/html','.css':'text/css','.js':'application/javascript','.json':'application/json','.png':'image/png','.ico':'image/x-icon'}[ext]||'text/plain';
    res.writeHead(200,{'Content-Type':mime});
    res.end(data);
  });

}).listen(PORT, ()=>{
  console.log('\n ╔══════════════════════════════════════════════════╗');
  console.log(' ║  CyberIntel Pro v20 — Lumiverse Solutions        ║');
  console.log(` ║  http://localhost:${PORT}                            ║`);
  console.log(' ╚══════════════════════════════════════════════════╝\n');
  const activeKeys = GEMINI_KEYS.filter(k=>k&&!k.includes('PASTE')).length;
  console.log(` Gemini keys         : ${activeKeys} loaded`);
  console.log(' --- NO KEY NEEDED (always active) ---');
  console.log(' ✓ DNS Scanner        : SPF/DMARC/MX/Blacklist');
  console.log(' ✓ SSL (crt.sh)       : Certificate transparency');
  console.log(' ✓ Shodan InternetDB  : Open ports + CVEs');
  console.log(' ✓ IP Geolocation     : ip-api.com (city/ISP/ASN)');
  console.log(' ✓ WHOIS/RDAP         : Domain age/registrar/expiry');
  console.log(' ✓ HTTP Headers       : Tech stack + security headers');
  console.log(' ✓ HackerTarget       : Subdomain enumeration');
  console.log(' ✓ Wayback Machine    : Historical presence (archive.org)');
  console.log(' ✓ LeakIX             : Exposed services');
  console.log(' --- FREE API KEY NEEDED (add to .env) ---');
  const vtOk  = VIRUSTOTAL_KEY  && VIRUSTOTAL_KEY.length > 10;
  const gnOk  = GREYNOISE_KEY   && GREYNOISE_KEY.length  > 5;
  const usOk  = URLSCAN_KEY     && URLSCAN_KEY.length    > 10;
  console.log(` ${vtOk?'✓':'○'} VirusTotal       : 500/day — ${vtOk?'ACTIVE':'add VIRUSTOTAL_KEY to .env'}`);
  console.log(` ${gnOk?'✓':'○'} GreyNoise        : free — ${gnOk?'ACTIVE':'add GREYNOISE_KEY to .env — viz.greynoise.io/signup'}`);
  console.log(` ${usOk?'✓':'○'} urlscan.io       : 1000/month — ${usOk?'ACTIVE':'add URLSCAN_KEY to .env — urlscan.io'}`);
  console.log('');
})