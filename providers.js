// providers.js — real, verifiable data sources for CyberIntel Pro
// Built-in https only (zero npm). Every record carries a source_url link so
// the data can be checked. Keys come from .env — no key = provider is skipped.
'use strict';
const https = require('https');

// ── low-level helpers ────────────────────────────────────────────────
function getJSON(url, headers = {}, timeout = 12000) {
  return new Promise(resolve => {
    let u; try { u = new URL(url); } catch { return resolve(null); }
    const req = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: 'GET', timeout,
      headers: { Accept: 'application/json', 'User-Agent': 'CyberIntel/1.0', ...headers }
    }, r => {
      let b = ''; r.on('data', c => { if (b.length < 800000) b += c; });
      r.on('end', () => { try { resolve({ status: r.statusCode, json: JSON.parse(b) }); }
                          catch { resolve({ status: r.statusCode, json: null, raw: b.slice(0, 300) }); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}
function postJSON(url, body, headers = {}, timeout = 12000) {
  return new Promise(resolve => {
    let u; try { u = new URL(url); } catch { return resolve(null); }
    const payload = JSON.stringify(body || {});
    const req = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: 'POST', timeout,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json',
                 'Content-Length': Buffer.byteLength(payload), ...headers }
    }, r => {
      let b = ''; r.on('data', c => { if (b.length < 800000) b += c; });
      r.on('end', () => { try { resolve({ status: r.statusCode, json: JSON.parse(b) }); }
                          catch { resolve({ status: r.statusCode, json: null, raw: b.slice(0, 300) }); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(payload); req.end();
  });
}

const HUNTER = process.env.HUNTER_API_KEY || '';
const SERPER = process.env.SERPER_API_KEY || '';   // optional generic SERP fallback

// ── Hunter.io: real emails found on the public web, WITH source URLs ──
// Domain Search — all emails for a domain, each with name/role/confidence/sources.
async function hunterDomainSearch(domain, limit = 15) {
  if (!HUNTER) return { ok: false, reason: 'HUNTER_API_KEY not set', emails: [], pattern: null };
  const r = await getJSON(`https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&limit=${limit}&api_key=${HUNTER}`);
  if (!r || r.status !== 200 || !r.json?.data)
    return { ok: false, reason: `Hunter HTTP ${r?.status || 'err'}`, emails: [], pattern: null };
  const d = r.json.data;
  const emails = (d.emails || []).map(e => ({
    email: e.value,
    name: [e.first_name, e.last_name].filter(Boolean).join(' ') || null,
    role: e.position || null,
    department: e.department || null,
    seniority: e.seniority || null,
    type: e.type || null,                                  // 'personal' | 'generic'
    confidence: typeof e.confidence === 'number' ? e.confidence : null, // 0–100
    accept_all: !!e.verification?.status && e.verification.status === 'accept_all',
    verified: e.verification?.status === 'valid',
    source: 'hunter',
    source_url: e.sources?.[0]?.uri || null,               // page where it was actually found
    sources_count: (e.sources || []).length,
    linkedin: e.linkedin || null,
  }));
  const pat = d.pattern ? d.pattern.replace('{first}', 'first').replace('{last}', 'last').replace('{f}', 'f') + '@' + domain : null;
  return { ok: true, emails, pattern: pat, organization: d.organization || null, accept_all: !!d.accept_all };
}

// Email Finder — most likely address for a specific person (name + domain).
async function hunterEmailFinder(domain, first, last) {
  if (!HUNTER || !first) return null;
  const r = await getJSON(`https://api.hunter.io/v2/email-finder?domain=${encodeURIComponent(domain)}&first_name=${encodeURIComponent(first)}&last_name=${encodeURIComponent(last || '')}&api_key=${HUNTER}`);
  const d = r?.json?.data; if (!d?.email) return null;
  return {
    email: d.email,
    name: [first, last].filter(Boolean).join(' '),
    role: d.position || null,
    confidence: typeof d.score === 'number' ? d.score : null,
    accept_all: !!d.accept_all,
    verified: d.verification?.status === 'valid',
    source: 'hunter',
    source_url: d.sources?.[0]?.uri || d.linkedin_url || null,
  };
}

// Email Verifier — deliverability of one address (status + accept_all + score).
async function hunterVerify(email) {
  if (!HUNTER) return null;
  const r = await getJSON(`https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${HUNTER}`);
  const d = r?.json?.data; if (!d) return null;
  return {
    email,
    status: d.status,                    // valid | invalid | accept_all | webmail | disposable | unknown
    score: typeof d.score === 'number' ? d.score : null,
    accept_all: !!d.accept_all,
    mx: !!d.mx_records,
    smtp_check: !!d.smtp_check,
    disposable: !!d.disposable,
    source_url: d.sources?.[0]?.uri || null,
  };
}

// ── Optional generic web search (Serper.dev) — returns real Google results ──
// Only used if SERPER_API_KEY is set. Google's own CSE API is closed to new signups.
async function serperSearch(query, num = 8) {
  if (!SERPER) return { ok: false, reason: 'SERPER_API_KEY not set', results: [] };
  const r = await postJSON('https://google.serper.dev/search', { q: query, num },
    { 'X-API-KEY': SERPER });
  const org = r?.json?.organic || [];
  return { ok: true, results: org.map(i => ({ title: i.title, link: i.link, snippet: i.snippet })) };
}

module.exports = { hunterDomainSearch, hunterEmailFinder, hunterVerify, serperSearch, getJSON, postJSON };
