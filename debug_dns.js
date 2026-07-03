const fs = require('fs');
const dns = require('dns').promises;
const https = require('https');

function httpsGet(opts, timeout=8000) { 
    return new Promise((res,rej) => { 
        const req = https.request(opts, r => { 
            let d=''; 
            r.on('data',c=>d+=c); 
            r.on('end',()=>{ 
                try{res(JSON.parse(d));}catch(e){res({_raw:d,_status:r.statusCode}); }
            }); 
        }); 
        req.setTimeout(timeout, ()=>{req.destroy();rej(new Error('Timeout'));}); 
        req.on('error',rej); 
        req.end(); 
    }); 
}

const MXTOOLBOX_KEY = '82523c16-12f6-4622-b113-62b9e76855af';

// Paste scanDNS logic below
async function scanDNS(domain) {
  const result = { domain, spf:{exists:false,record:null,policy:null,issues:[]}, dmarc:{exists:false,record:null,policy:null,issues:[]}, mx:{exists:false,records:[]}, blacklist:{listed:false,details:[]}, ssl:{checked:false}, summary_gaps:[], lumiverse_opportunities:[] };

  let dmarcChecked = false;
  let spfChecked = false;

  // 1. MxToolBox API (if key provided)
  if (MXTOOLBOX_KEY && !MXTOOLBOX_KEY.includes('PASTE')) {
    try {
      const headers = { 'Authorization': MXTOOLBOX_KEY, 'Accept': 'application/json' };
      const [dmarcRes, spfRes] = await Promise.all([
        httpsGet({ hostname: 'api.mxtoolbox.com', path: '/api/v1/lookup/dmarc/' + domain, method: 'GET', headers }, 8000).catch(()=>null),
        httpsGet({ hostname: 'api.mxtoolbox.com', path: '/api/v1/lookup/spf/' + domain, method: 'GET', headers }, 8000).catch(()=>null)
      ]);
      
      console.log('DMARC RES RECORDS:', dmarcRes ? dmarcRes.Records : null);

      if (dmarcRes) {
        let dInfo = null;
        if (dmarcRes.Records && dmarcRes.Records.length > 0) {
          dInfo = dmarcRes.Records[0];
        } else if (dmarcRes.Information) {
          const rec = dmarcRes.Information.find(i => i && (i.Name === 'record' || (i.Description && i.Description.includes('v=DMARC1'))));
          if (rec) dInfo = rec.Description || rec.Value || '';
        }
        console.log('DMARC dInfo:', dInfo);
        if (dInfo && typeof dInfo === 'string' && dInfo.toLowerCase().includes('v=dmarc1')) {
          result.dmarc.exists = true;
          result.dmarc.record = dInfo;
          const pm = dInfo.match(/\bp=\s*([a-z]+)/i);
          result.dmarc.policy = pm ? pm[1].toLowerCase() : 'none';
          if (result.dmarc.policy === 'none') result.dmarc.issues.push('DMARC p=none — phishing NOT blocked');
          else if (result.dmarc.policy === 'quarantine') result.dmarc.issues.push('DMARC p=quarantine — upgrade to p=reject');
          dmarcChecked = true;
        }
      }
      
      if (spfRes) {
        let sInfo = null;
        if (spfRes.Records && spfRes.Records.length > 0) {
          sInfo = spfRes.Records[0];
        } else if (spfRes.Information) {
          const rec = spfRes.Information.find(i => i && (i.Type === 'record' || i.Name === 'record' || (i.Description && i.Description.includes('v=spf1'))));
          if (rec) sInfo = rec.Description || rec.Value || '';
        }
        console.log('SPF sInfo:', sInfo);
        if (sInfo && typeof sInfo === 'string' && sInfo.toLowerCase().includes('v=spf1')) {
          result.spf.exists = true;
          result.spf.record = sInfo;
          result.spf.policy = sInfo.includes('-all') ? 'hard_fail' : sInfo.includes('~all') ? 'soft_fail' : 'permissive';
          if (sInfo.includes('~all')) result.spf.issues.push('SPF ~all — spoofed emails may reach inbox');
          if (sInfo.includes('+all')) result.spf.issues.push('SPF +all — ANYONE can send as this domain');
          spfChecked = true;
        }
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
      result.spf.issues.push('No SPF record — domain open to email spoofing');
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
      result.dmarc.issues.push('No DMARC — domain impersonation CRITICAL risk');
    }
  }

  return result;
}

scanDNS('zepto.com').then(r => console.log('FINAL RESULT:', JSON.stringify({dmarc: r.dmarc, spf: r.spf}, null, 2))).catch(console.error);
