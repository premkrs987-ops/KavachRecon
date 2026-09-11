// KavachRecon — web intelligence: technology fingerprinting, WAF/CDN, security posture,
// robots/sitemap, endpoint discovery, JavaScript intelligence, cloud signals
import { uid, run, now, q, q1 } from '../../db.js';
import { httpProbe, parseTitle } from '../../lib/netutil.js';
import { fetchWithErr } from './passive.js';
import crypto from 'node:crypto';

function obs(ctx) {
  return q(`SELECT w.*, e.content AS evidence_content FROM web_observations w LEFT JOIN evidence e ON e.id = w.evidence_id WHERE w.scan_id = ? AND w.ok = 1`, [ctx.scan.id]);
}
function parseObs(row) {
  return {
    url: row.url, final_url: row.final_url, status: row.status_code, title: row.title,
    headers: safeJson(row.headers), tls: row.tls ? safeJson(row.tls) : null,
    body: safeJson(row.evidence_content || '{}')?.body_excerpt || '', redirect_chain: safeJson(row.redirect_chain || '[]'),
  };
}
const safeJson = (s) => { try { return JSON.parse(s); } catch { return {}; } };
const lower = (h) => Object.fromEntries(Object.entries(h || {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(', ') : v]));
const normV = (v) => Array.isArray(v) ? v.join(', ') : (v ?? null);

/* ---------------- Technology fingerprinting ---------------- */
const TECH_SIGNATURES = [
  { name: 'nginx', cat: 'web-server', header: 'server', re: /nginx\/?([\d.]+)?/i },
  { name: 'Apache httpd', cat: 'web-server', header: 'server', re: /Apache\/([\d.]+)?/i },
  { name: 'Microsoft IIS', cat: 'web-server', header: 'server', re: /Microsoft-IIS\/([\d.]+)?/i },
  { name: 'LiteSpeed', cat: 'web-server', header: 'server', re: /LiteSpeed/i },
  { name: 'Caddy', cat: 'web-server', header: 'server', re: /Caddy/i },
  { name: 'Kestrel', cat: 'web-server', header: 'server', re: /Kestrel/i },
  { name: 'Express', cat: 'web-framework', header: 'x-powered-by', re: /Express/i },
  { name: 'PHP', cat: 'language', header: 'x-powered-by', re: /PHP\/?([\d.]+)?/i },
  { name: 'ASP.NET', cat: 'framework', header: 'x-powered-by', re: /ASP\.NET/i },
  { name: 'Next.js', cat: 'framework', header: 'x-powered-by', re: /Next\.js/i },
  { name: 'cloudflare', cat: 'edge', header: 'server', re: /cloudflare/i },
];
const HTML_SIGNATURES = [
  { name: 'React', cat: 'js-framework', re: /data-reactroot|__NEXT_DATA__|\/_next\//i, conf: 'MEDIUM' },
  { name: 'Vue.js', cat: 'js-framework', re: /data-v-[0-9a-f]{8}|Vue\.js/, conf: 'MEDIUM' },
  { name: 'Angular', cat: 'js-framework', re: /ng-version=|angular[^a-z]/i, conf: 'MEDIUM' },
  { name: 'WordPress', cat: 'cms', re: /wp-content|wp-includes/i, conf: 'HIGH' },
  { name: 'Drupal', cat: 'cms', re: /Drupal|sites\/default\/files/i, conf: 'HIGH' },
  { name: 'Joomla', cat: 'cms', re: /Joomla!/i, conf: 'HIGH' },
  { name: 'jQuery', cat: 'js-library', re: /jquery[.\-]?([\d.]+)?(\.min)?\.js/i, conf: 'HIGH' },
  { name: 'Bootstrap', cat: 'css-framework', re: /bootstrap[.\-]?([\d.]+)?(\.min)?\.(css|js)/i, conf: 'MEDIUM' },
  { name: 'Shopify', cat: 'ecommerce', re: /cdn\.shopify\.com|Shopify\.theme/i, conf: 'HIGH' },
  { name: 'Google Analytics', cat: 'analytics', re: /google-analytics\.com\/(ga|analytics)\.js|gtag\/js/i, conf: 'HIGH' },
  { name: 'Google Tag Manager', cat: 'analytics', re: /googletagmanager\.com/i, conf: 'HIGH' },
  { name: 'Font Awesome', cat: 'ui', re: /fontawesome/i, conf: 'MEDIUM' },
];
const COOKIE_SIGNATURES = [
  { name: 'PHP session', re: /PHPSESSID/i, cat: 'backend' },
  { name: 'Express session', re: /connect\.sid/i, cat: 'backend' },
  { name: 'Laravel session', re: /laravel_session|XSRF-TOKEN/i, cat: 'backend' },
  { name: 'ASP.NET session', re: /ASP\.NET_SessionId|ARRAffinity/i, cat: 'backend' },
  { name: 'Cloudflare', re: /__cf_bm|cf_clearance/i, cat: 'edge' },
];

export const techFingerprint = {
  key: 'tech_fingerprint', name: 'Technology Fingerprinting', description: 'Identifies technologies strictly from observed response headers, HTML content and cookies. Only evidence-backed detections are recorded.',
  timeoutMs: 60_000,
  async run(ctx) {
    const rows = obs(ctx);
    if (!rows.length) return { status: 'NOT_APPLICABLE', detail: { reason: 'No reachable HTTP/HTTPS observations exist from the probing module — no technologies can be fingerprinted. This is NOT evidence that the target uses no technologies.' } };
    let detected = 0;
    for (const row of rows) {
      const o = parseObs(row);
      const H = lower(o.headers);
      const urlAsset = ctx.store.addAsset({ type: 'URL', key: (o.final_url || o.url).toLowerCase(), value: o.final_url || o.url });
      const add = (name, version, cat, method, match, confidence) => {
        const key = `${name}@${(o.final_url || o.url).toLowerCase()}`;
        const techId = ctx.store.addAsset({ type: 'TECHNOLOGY', key, value: version ? `${name} ${version}` : name, parent_id: urlAsset, confidence });
        const evId = ctx.store.addEvidence({
          module_key: 'tech_fingerprint', asset_id: techId, kind: 'TECH_DETECTION', source: method,
          summary: `${name}${version ? ` ${version}` : ''} detected on ${o.url} via ${method}: "${String(match).slice(0, 120)}"`,
          content: { url: o.url, name, version: version || null, method, match: String(match).slice(0, 300), category: cat },
        });
        run(`INSERT INTO technologies (id, scan_id, asset_id, name, version, category, detection_method, raw_match, confidence, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          [uid('tech'), ctx.scan.id, techId, name, version || null, cat, method, String(match).slice(0, 300), confidence, evId, now()]);
        ctx.store.addEdge(urlAsset, techId, 'USES_TECHNOLOGY');
        detected++;
      };
      for (const sig of TECH_SIGNATURES) {
        const hv = H[sig.header];
        if (hv) { const m = hv.match(sig.re); if (m) add(sig.name, m[1] || null, sig.cat, `${sig.header} header`, hv, 'HIGH'); }
      }
      for (const sig of HTML_SIGNATURES) {
        const m = (o.body || '').match(sig.re);
        if (m) {
          const ver = m[1] || null;
          add(sig.name, ver, sig.cat, 'HTML content pattern', m[0], sig.conf);
        }
      }
      const setCookies = [].concat(H['set-cookie'] ? [H['set-cookie']] : []).join('; ');
      for (const sig of COOKIE_SIGNATURES) {
        if (sig.re.test(setCookies)) add(sig.name, null, sig.cat, 'Set-Cookie cookie name', setCookies.slice(0, 150), 'MEDIUM');
      }
      const gen = (o.body || '').match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i);
      if (gen) add(gen[1].trim(), null, 'generator-meta', 'meta generator tag', gen[0], 'HIGH');
    }
    return { status: detected ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { detected, note: detected ? null : 'No technology signatures matched the collected evidence. No conclusion about absence of technologies is implied.' } };
  },
};

/* ---------------- WAF / CDN / Perimeter ---------------- */
const PERIM_HEADERS = [
  { kind: 'CDN', name: 'Cloudflare', re: /cloudflare/i, headers: ['cf-ray', 'cf-cache-status', '__cf_bm'], conf: 'HIGH' },
  { kind: 'CDN', name: 'CloudFront', re: /cloudfront/i, headers: ['x-amz-cf-id', 'x-amz-cf-pop', 'via'], conf: 'HIGH' },
  { kind: 'CDN', name: 'Fastly', re: /fastly/i, headers: ['x-served-by', 'x-cache', 'fastly-restarts'], conf: 'HIGH' },
  { kind: 'CDN', name: 'Akamai', re: /akamai/i, headers: ['x-akamai-transformed', 'server'], conf: 'MEDIUM' },
  { kind: 'CDN', name: 'Azure CDN / Front Door', re: /(azureedge|azurefd|microsoft-azure)/i, headers: ['x-azure-ref', 'x-cache'], conf: 'HIGH' },
  { kind: 'CDN', name: 'Google Cloud CDN', re: /(gc[ds]?|gke|GoogleFrontend)/i, headers: ['via'], conf: 'LOW' },
  { kind: 'CDN', name: 'CDN77', re: /cdn77/i, headers: ['cdn77'], conf: 'HIGH' },
  { kind: 'CDN', name: 'StackPath / MaxCDN', re: /(stackpath|maxcdn)/i, headers: [], conf: 'MEDIUM' },
  { kind: 'WAF', name: 'Cloudflare WAF', re: /(cloudflare|cf-ray|captcha-bypass|Attention Required)/i, headers: ['cf-mitigated', 'server'], conf: 'MEDIUM' },
  { kind: 'WAF', name: 'AWS WAF', re: /awswaf/i, headers: ['x-amzn-waf-action', 'server'], conf: 'HIGH' },
  { kind: 'WAF', name: 'Sucuri', re: /sucuri/i, headers: ['x-sucuri-id', 'x-sucuri-cache', 'server'], conf: 'HIGH' },
  { kind: 'WAF', name: 'Imperva / Incapsula', re: /(incapsula|imperva|visid_incap)/i, headers: ['x-iinfo', 'set-cookie'], conf: 'HIGH' },
  { kind: 'WAF', name: 'F5 BIG-IP ASM', re: /(BIGipServer|TS=)/i, headers: ['set-cookie'], conf: 'MEDIUM' },
  { kind: 'WAF', name: 'ModSecurity', re: /mod_security|modsecurity/i, headers: ['server'], conf: 'LOW' },
  { kind: 'PROXY', name: 'Squid', re: /squid/i, headers: ['via', 'server'], conf: 'MEDIUM' },
  { kind: 'PROXY', name: 'Varnish', re: /varnish/i, headers: ['via', 'x-varnish', 'server'], conf: 'MEDIUM' },
  { kind: 'EDGE', name: 'Vercel', re: /(vercel|now)/i, headers: ['x-vercel-id', 'x-vercel-cache', 'server'], conf: 'HIGH' },
  { kind: 'EDGE', name: 'Netlify', re: /netlify/i, headers: ['x-nf-request-id', 'server'], conf: 'HIGH' },
  { kind: 'EDGE', name: 'GitHub Pages', re: /github/i, headers: ['x-github-request-id'], conf: 'MEDIUM' },
  { kind: 'EDGE', name: 'Render / Fly.io', re: /(render|fly\.io|flyio)/i, headers: ['server', 'via'], conf: 'LOW' },
];

export const wafCdnDetect = {
  key: 'waf_cdn', name: 'WAF / CDN / Perimeter Detection', description: 'Detects edge infrastructure strictly from response headers, cookies and body markers. Absence of detections is never reported as "no WAF exists".',
  timeoutMs: 45_000,
  async run(ctx) {
    const rows = obs(ctx);
    if (!rows.length) return { status: 'NOT_APPLICABLE', detail: { reason: 'No HTTP observations available to analyse for perimeter infrastructure.' } };
    let detected = 0;
    const seenNames = new Set();
    for (const row of rows) {
      const o = parseObs(row);
      const H = lower(o.headers);
      const urlAsset = ctx.store.addAsset({ type: 'URL', key: (o.final_url || o.url).toLowerCase(), value: o.final_url || o.url });
      for (const sig of PERIM_HEADERS) {
        if (seenNames.has(`${sig.kind}:${sig.name}`)) continue;
        let hit = null;
        for (const hname of sig.headers) { if (H[hname] && sig.re.test(H[hname])) { hit = { header: hname, value: normV(H[hname]).slice(0, 200) }; break; } }
        if (!hit && H['server'] && sig.headers.includes('server') && sig.re.test(H['server'])) hit = { header: 'server', value: normV(H['server']).slice(0, 200) };
        if (!hit && H['via'] && sig.re.test(H['via']) && ['CDN', 'PROXY'].includes(sig.kind)) hit = { header: 'via', value: normV(H['via']).slice(0, 200) };
        if (hit) {
          seenNames.add(`${sig.kind}:${sig.name}`);
          const pId = ctx.store.addAsset({ type: 'CLOUD', key: `${sig.kind.toLowerCase()}:${sig.name}`.toLowerCase(), value: `${sig.kind}: ${sig.name}`, confidence: sig.conf });
          const evId = ctx.store.addEvidence({
            module_key: 'waf_cdn', asset_id: pId, kind: 'PERIMETER_DETECTION', source: `${hit.header} response header on ${o.url}`,
            summary: `${sig.kind} "${sig.name}" indicated by ${hit.header}="${hit.value}"`,
            content: { url: o.url, kind: sig.kind, name: sig.name, method: 'header-signature', match: hit },
          });
          run(`INSERT INTO perimeter (id, scan_id, asset_id, kind, name, detection_method, raw_match, confidence, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
            [uid('per'), ctx.scan.id, pId, sig.kind, sig.name, `response header (${hit.header})`, hit.value, sig.conf, evId, now()]);
          ctx.store.addEdge(urlAsset, pId, 'BEHIND');
          detected++;
        }
      }
    }
    return { status: detected ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { detected, note: detected ? null : 'No perimeter signatures matched the collected evidence. Detection returning no result must NOT be interpreted as "no WAF/CDN exists".' } };
  },
};

/* ---------------- Security posture (headers, cookies, TLS, redirects) ---------------- */
const HEADER_CHECKS = [
  { kind: 'HSTS', header: 'strict-transport-security' },
  { kind: 'CSP', header: 'content-security-policy' },
  { kind: 'XFO', header: 'x-frame-options' },
  { kind: 'XCTO', header: 'x-content-type-options' },
  { kind: 'REFERRER', header: 'referrer-policy' },
  { kind: 'PERMISSIONS', header: 'permissions-policy' },
];

export const securityPosture = {
  key: 'security_posture', name: 'Security Posture (headers / cookies / TLS)', description: 'Records actual presence/absence of security headers, cookie attributes, HTTPS redirect behaviour and TLS properties — each tied to the exact URL it came from.',
  timeoutMs: 45_000,
  async run(ctx) {
    const rows = obs(ctx);
    if (!rows.length) return { status: 'NOT_APPLICABLE', detail: { reason: 'No HTTP observations available to assess posture from.' } };
    let count = 0;
    for (const row of rows) {
      const o = parseObs(row);
      const H = lower(o.headers);
      const url = o.final_url || o.url;
      const urlAsset = ctx.store.addAsset({ type: 'URL', key: url.toLowerCase(), value: url });
      for (const chk of HEADER_CHECKS) {
        const present = H[chk.header];
        const evId = ctx.store.addEvidence({
          module_key: 'security_posture', asset_id: urlAsset, kind: 'SECURITY_HEADER', source: `Response headers of ${url}`,
          summary: present ? `${chk.kind} header present on ${url}: "${normV(present).slice(0, 200)}"` : `${chk.kind} header ABSENT on ${url} (status ${o.status})`,
          content: { url, header: chk.header, present: !!present, value: present ? normV(present) : null, response_status: o.status },
        });
        const state = present ? 'PRESENT' : 'MISSING';
        run(`INSERT INTO posture (id, scan_id, asset_id, url, kind, state, header, value, detail, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          [uid('pos'), ctx.scan.id, urlAsset, url, chk.kind, state, chk.header, present ? normV(present) : null, JSON.stringify({ status: o.status }), evId, now()]);
        count++;
      }
      // cookies
      const cookies = normV(H['set-cookie'] || '');
      if (cookies) {
        const parts = cookies.split(/(?=(?:,\s*)?[\w.-]+=[^=;]*;)/).filter(Boolean).slice(0, 12);
        for (const c of parts) {
          const name = (c.split('=')[0] || '').trim();
          if (!name) continue;
          const flags = { secure: /secure/i.test(c), httponly: /httponly/i.test(c), samesite: (c.match(/samesite=(\w+)/i) || [])[1] || null };
          const state = flags.secure && flags.httponly ? 'SECURE_FLAGS' : 'WEAK_FLAGS';
          const evId = ctx.store.addEvidence({
            module_key: 'security_posture', asset_id: urlAsset, kind: 'COOKIE', source: `Set-Cookie on ${url}`,
            summary: `Cookie "${name}" on ${url}: Secure=${flags.secure}, HttpOnly=${flags.httponly}, SameSite=${flags.samesite || 'unset'}`,
            content: { url, cookie_name: name, ...flags, raw: c.slice(0, 300) },
          });
          run(`INSERT INTO posture (id, scan_id, asset_id, url, kind, state, header, value, detail, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
            [uid('pos'), ctx.scan.id, urlAsset, url, 'COOKIE', state, name, c.slice(0, 300), JSON.stringify(flags), evId, now()]);
          count++;
        }
      }
      // https redirect observation (http->https)
      if (o.url.startsWith('http:') && o.chain.length) {
        const first = o.chain[0];
        if (first.location && first.location.startsWith('https:')) {
          const evId = ctx.store.addEvidence({ module_key: 'security_posture', asset_id: urlAsset, kind: 'HTTPS_REDIRECT', source: `Redirect chain of ${o.url}`, summary: `${o.url} redirects to HTTPS (${first.status} → ${first.location})`, content: { url: o.url, chain: o.chain } });
          run(`INSERT INTO posture (id, scan_id, asset_id, url, kind, state, header, value, detail, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
            [uid('pos'), ctx.scan.id, urlAsset, o.url, 'HTTPS_REDIRECT', 'ENFORCED', null, first.location, JSON.stringify({ status: first.status }), evId, now()]);
          count++;
        }
      } else if (o.url.startsWith('http:') && o.status && !o.chain.length) {
        const evId = ctx.store.addEvidence({ module_key: 'security_posture', asset_id: urlAsset, kind: 'HTTPS_REDIRECT', source: `Response of ${o.url}`, summary: `${o.url} served content over plain HTTP without redirecting to HTTPS (status ${o.status})`, content: { url: o.url, status: o.status } });
        run(`INSERT INTO posture (id, scan_id, asset_id, url, kind, state, header, value, detail, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          [uid('pos'), ctx.scan.id, urlAsset, o.url, 'HTTPS_REDIRECT', 'NOT_ENFORCED', null, null, JSON.stringify({ status: o.status }), evId, now()]);
        count++;
      }
      // TLS posture
      const tls = o.tls;
      if (tls?.ok) {
        const legacy = tls.legacySupport?.tls10 || tls.legacySupport?.tls11;
        const evId = ctx.store.addEvidence({ module_key: 'security_posture', asset_id: urlAsset, kind: 'TLS', source: `TLS handshake with ${new URL(url).host}`, summary: `${url}: negotiated ${tls.protocol}, cipher ${tls.cipher}${legacy ? ', legacy TLSv1.0/1.1 ACCEPTED' : ''}`, content: tls });
        run(`INSERT INTO posture (id, scan_id, asset_id, url, kind, state, header, value, detail, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          [uid('pos'), ctx.scan.id, urlAsset, url, 'TLS', legacy ? 'WEAK_PROTOCOL' : 'OK', tls.protocol, tls.cipher, JSON.stringify({ legacy }), evId, now()]);
        count++;
        if (tls.cert) {
          const cert = tls.cert;
          const notAfter = new Date(cert.valid_to);
          const days = Math.round((notAfter - Date.now()) / 86400000);
          const expEv = ctx.store.addEvidence({ module_key: 'security_posture', asset_id: urlAsset, kind: 'TLS_CERT', source: `Certificate presented by ${new URL(url).host}`, summary: `Certificate for ${url}: CN=${cert.subject?.CN}, issuer=${cert.issuer?.O || cert.issuer?.CN}, valid_to=${cert.valid_to} (${days} days remaining)`, content: { cert, days_remaining: days } });
          run(`INSERT INTO posture (id, scan_id, asset_id, url, kind, state, header, value, detail, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
            [uid('pos'), ctx.scan.id, urlAsset, url, 'CERT', days < 0 ? 'EXPIRED' : days < 30 ? 'EXPIRING_SOON' : 'VALID', cert.subject?.CN || null, `valid_to=${cert.valid_to}`, JSON.stringify({ days_remaining: days, issuer: cert.issuer }), expEv, now()]);
          count++;
        }
      }
    }
    return { status: 'COMPLETED', detail: { observations: count } };
  },
};

/* ---------------- robots.txt / sitemap ---------------- */
export const robotsSitemap = {
  key: 'robots_sitemap', name: 'robots.txt & Sitemap Analysis', description: 'Fetches and parses robots.txt and sitemap.xml from each observed origin, recording directives and discovered URLs verbatim.',
  timeoutMs: 120_000,
  when: (ctx) => obs(ctx).length > 0,
  whenReason: 'No reachable HTTP origins to query for robots.txt/sitemap.',
  async run(ctx) {
    const origins = [...new Set(obs(ctx).map(o => { try { return new URL(o.final_url || o.url).origin; } catch { return null; } }).filter(Boolean))];
    let urlsFound = 0, robotsFound = 0;
    for (const origin of origins.slice(0, 12)) {
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
      if (ctx.netGuard(new URL(origin).hostname)) continue;
      const r = await httpProbe(`${origin}/robots.txt`, { timeout: 8000, rateLimiter: ctx.rate, host: new URL(origin).hostname, maxBytes: 100_000 });
      if (r.ok && r.status === 200 && /user-agent|sitemap|disallow/i.test(r.body || '')) {
        robotsFound++;
        const originAsset = ctx.store.addAsset({ type: 'URL', key: `${origin}/`.toLowerCase(), value: `${origin}/` });
        const evId = ctx.store.addEvidence({
          module_key: 'robots_sitemap', asset_id: originAsset, kind: 'ROBOTS_TXT', source: `${origin}/robots.txt (HTTP ${r.status})`,
          summary: `robots.txt retrieved from ${origin}: ${(r.body.match(/Disallow/gi) || []).length} Disallow, ${(r.body.match(/Sitemap/gi) || []).length} Sitemap directives`,
          content: { url: `${origin}/robots.txt`, status: r.status, body: (r.body || '').slice(0, 8000), headers: r.headers },
        });
        for (const line of r.body.split('\n')) {
          const sm = line.match(/^\s*sitemap:\s*(\S+)/i);
          if (sm) {
            const smUrl = ctx.store.addAsset({ type: 'URL', key: sm[1].toLowerCase(), value: sm[1], parent_id: originAsset });
            ctx.store.addEdge(originAsset, smUrl, 'DECLARES_SITEMAP');
          }
          const dis = line.match(/^\s*disallow:\s*(\S*)/i);
          if (dis && dis[1]) {
            const path = new URL(dis[1], origin).href;
            const pUrl = ctx.store.addAsset({ type: 'URL', key: path.toLowerCase(), value: path, parent_id: originAsset, confidence: 'LOW' });
            ctx.store.addEdge(originAsset, pUrl, 'DISALLOWS_PATH');
            recordEndpoint(ctx, { url: path, status: null, classification: classifyPath(path, null), evId, note: `Referenced in robots.txt Disallow (${origin}). robots.txt directives are declarative — existence/HTTP status not verified unless probed.` });
            urlsFound++;
          }
        }
      } else {
        const evId = ctx.store.addEvidence({ module_key: 'robots_sitemap', kind: 'ROBOTS_TXT', source: `${origin}/robots.txt`, summary: `robots.txt ${r.ok ? `returned HTTP ${r.status}` : `unreachable (${r.error})`} for ${origin}`, content: { url: `${origin}/robots.txt`, status: r.status || null, error: r.error || null } });
        // record nothing as URL asset
        ctx.log(`robots.txt ${origin}: ${r.ok ? r.status : r.error}`);
      }
      // sitemap.xml direct
      const s = await httpProbe(`${origin}/sitemap.xml`, { timeout: 8000, rateLimiter: ctx.rate, host: new URL(origin).hostname, maxBytes: 300_000 });
      if (s.ok && s.status === 200 && /<urlset|<sitemapindex/i.test(s.body || '')) {
        const locs = [...s.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map(m => m[1]).slice(0, 300);
        const originAsset = ctx.store.addAsset({ type: 'URL', key: `${origin}/`.toLowerCase(), value: `${origin}/` });
        const evId = ctx.store.addEvidence({ module_key: 'robots_sitemap', asset_id: originAsset, kind: 'SITEMAP', source: `${origin}/sitemap.xml (HTTP ${s.status})`, summary: `sitemap.xml parsed from ${origin}: ${locs.length} <loc> URLs`, content: { url: `${origin}/sitemap.xml`, locs: locs.slice(0, 100) } });
        for (const loc of locs) {
          if (ctx.netGuard(loc)) continue;
          const lId = ctx.store.addAsset({ type: 'URL', key: loc.toLowerCase(), value: loc, parent_id: originAsset });
          ctx.store.addEdge(originAsset, lId, 'SITEMAP_URL');
          recordEndpoint(ctx, { url: loc, status: null, classification: classifyPath(loc, null), evId, note: 'Listed in sitemap.xml; HTTP status recorded only when probed.' });
          urlsFound++;
        }
      }
    }
    return { status: (robotsFound || urlsFound) ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { origins_checked: origins.length, robots_found: robotsFound, urls_discovered: urlsFound } };
  },
};

/* ---------------- Endpoint discovery ---------------- */
function classifyPath(url, title) {
  const u = url.toLowerCase();
  const t = (title || '').toLowerCase();
  const table = [
    ['LOGIN', [/login/, /signin/, /sign-in/, /log-in/, /wp-login/]],
    ['AUTHENTICATION', [/oauth/, /auth/, /sso/, /token/, /session/, /saml/]],
    ['ADMIN', [/admin/, /administrator/, /manager/, /wp-admin/, /cpanel/, /dashboard/, /console/]],
    ['API', [/\/api(\/|$)/, /\/v\d+(\/|$)/, /graphql/, /rest\//, /swagger/, /openapi/]],
    ['UPLOAD', [/upload/, /import/]],
    ['DOCUMENTATION', [/docs?($|\/)/, /documentation/, /manual/, /help/, /readme/, /.md$/, /api-docs/]],
    ['STATIC', [/\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|pdf|zip|mp4|webp|xml|txt)(\?|$)/]],
    ['POTENTIALLY_SENSITIVE', [/\.git(\/|$)/, /\.env/, /\.svn/, /backup/, /\.bak$/, /debug/, /phpinfo/, /\.sql$/, /\.ds_store/, /config\.json/, /\.aws/, /credentials/, /private/, /\.htaccess/, /web\.config/, /actuator/, /server-status/, /\.well-known\/security/]],
  ];
  for (const [cls, patterns] of table) {
    if (patterns.some(rx => rx.test(u) || (title && rx.test(t)))) return cls;
  }
  return 'PUBLIC';
}

export function recordEndpoint(ctx, { url, status, classification, evId, note, assetId, title }) {
  const cls = classification || classifyPath(url, title);
  const id = uid('end');
  const uAsset = assetId || ctx.store.addAsset({ type: 'ENDPOINT', key: url.toLowerCase(), value: url });
  run(`INSERT INTO endpoints (id, scan_id, asset_id, url, classification, status_code, verified, evidence_id, note, collected_at) VALUES (?,?,?,?,?,?,0,?,?,?)`,
    [id, ctx.scan.id, uAsset, url, cls, status ?? null, evId, note || '', now()]);
  ctx.store.bump('endpoint_discovery');
  return id;
}

export const endpointDiscovery = {
  key: 'endpoint_discovery', name: 'Endpoint Discovery & Classification', description: 'Extracts endpoints from observed HTML (links, forms, scripts) and classifies them with evidence. Observation of an admin-looking path is recorded as "potential" — never as a confirmed vulnerability.',
  timeoutMs: 90_000,
  when: (ctx) => obs(ctx).length > 0,
  whenReason: 'No reachable HTTP pages from which to extract endpoints.',
  async run(ctx) {
    const rows = obs(ctx);
    let count = 0;
    for (const row of rows.slice(0, 20)) {
      const o = parseObs(row);
      const origin = (() => { try { return new URL(o.final_url || o.url).origin; } catch { return null; } })();
      if (!origin) continue;
      const pageEvAsset = ctx.store.addAsset({ type: 'URL', key: (o.final_url || o.url).toLowerCase(), value: o.final_url || o.url });
      const links = [...(o.body || '').matchAll(/(?:href|src|action)\s*=\s*["']([^"'#\s]{3,300})["']/gi)].map(m => m[1]);
      const uniq = new Set();
      for (const raw of links) {
        if (uniq.size > 250) break;
        let abs; try { abs = new URL(raw, origin).href; } catch { continue; }
        if (!abs.startsWith('http')) continue;
        if (ctx.netGuard(abs)) continue;
        if (uniq.has(abs)) continue; uniq.add(abs);
        const evId = ctx.store.addEvidence({
          module_key: 'endpoint_discovery', kind: 'ENDPOINT_REFERENCE', source: `HTML of ${o.final_url || o.url} (status ${o.status})`,
          summary: `Reference "${raw.slice(0, 100)}" found in page markup of ${o.final_url || o.url}`,
          content: { page: o.final_url || o.url, raw_ref: raw, resolved: abs, page_title: o.title },
        });
        recordEndpoint(ctx, { url: abs, status: null, evId, note: `Referenced from page ${o.final_url || o.url}. HTTP status not verified unless probed.`, assetId: pageEvAsset ? undefined : undefined });
        count++;
      }
    }
    // also classify already-observed URLs (probed ones have status codes)
    for (const row of rows) {
      const o = parseObs(row);
      const existing = q1(`SELECT id FROM endpoints WHERE scan_id = ? AND url = ?`, [ctx.scan.id, o.final_url || o.url]);
      if (!existing) {
        const evId = row.evidence_id;
        recordEndpoint(ctx, { url: o.final_url || o.url, status: o.status, evId, note: `Directly probed — HTTP ${o.status} observed.`, title: o.title });
        count++;
      } else {
        run(`UPDATE endpoints SET status_code = ?, classification = ? WHERE id = ?`, [o.status, classifyPath(o.final_url || o.url, o.title), existing.id]);
      }
    }
    return { status: count ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { endpoints: count } };
  },
};

/* ---------------- JavaScript intelligence ---------------- */
const SECRET_PATTERNS = [
  { kind: 'AWS Access Key ID', re: /AKIA[0-9A-Z]{16}/g, confidence: 'HIGH', sev: 'HIGH' },
  { kind: 'Google API Key', re: /AIza[0-9A-Za-z\-_]{35}/g, confidence: 'HIGH', sev: 'HIGH' },
  { kind: 'GitHub Token (classic)', re: /gh[pousr]_[0-9A-Za-z]{36,}/g, confidence: 'HIGH', sev: 'HIGH' },
  { kind: 'Slack Token', re: /xox[baprs]-[0-9A-Za-z\-]{10,}/g, confidence: 'HIGH', sev: 'MEDIUM' },
  { kind: 'Stripe Live Key', re: /sk_live_[0-9A-Za-z]{16,}/g, confidence: 'HIGH', sev: 'CRITICAL' },
  { kind: 'Private Key Block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, confidence: 'HIGH', sev: 'CRITICAL' },
  { kind: 'JWT', re: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g, confidence: 'MEDIUM', sev: 'MEDIUM' },
  { kind: 'Generic API Key Assignment', re: /(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["'][A-Za-z0-9_\-./+=]{16,}["']/gi, confidence: 'LOW', sev: 'MEDIUM' },
];

function redact(match) {
  const s = String(match);
  if (s.length <= 8) return s.slice(0, 2) + '****';
  return s.slice(0, 4) + '****' + s.slice(-2);
}

export const jsIntel = {
  key: 'js_intel', name: 'JavaScript Intelligence', description: 'Fetches observed JavaScript resources and extracts API routes, endpoint references, domains, config references, public identifiers and potential secrets. All potential secrets are redacted and start UNVERIFIED.',
  timeoutMs: 300_000,
  when: (ctx) => obs(ctx).length > 0,
  whenReason: 'No reachable pages from which to collect JavaScript resources.',
  async run(ctx) {
    const rows = obs(ctx).slice(0, 20);
    const jsUrls = new Set();
    for (const row of rows) {
      const o = parseObs(row);
      const origin = (() => { try { return new URL(o.final_url || o.url).origin; } catch { return null; } })();
      if (!origin) continue;
      for (const m of (o.body || '').matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
        try { const abs = new URL(m[1], origin).href; if (abs.endsWith('.js') || /\.js\?/.test(abs)) jsUrls.add(abs); } catch {}
      }
      // inline script inspection for routes
      const inlineSecrets = scanForSecrets(`// inline:${o.url}\n` + (o.body || '').slice(0, 200_000));
      if (inlineSecrets.length) recordSecrets(ctx, { jsId: null, pageUrl: o.url, secrets: inlineSecrets, inline: true });
    }
    if (!jsUrls.size) return { status: 'COMPLETED_NO_RESULTS', detail: { reason: 'No external .js resources were referenced by the observed pages (or no pages were reachable). No JS analysis was possible — this does not imply the application has no JavaScript exposure.' } };
    let fetched = 0, routes = 0, refs = 0, secretsFound = 0;
    let budget = ctx.cfg.max_js_fetch;
    for (const jsUrl of jsUrls) {
      if (budget-- <= 0) break;
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
      const host = (() => { try { return new URL(jsUrl).host; } catch { return null; } })();
      if (!host || ctx.netGuard(host) || ctx.netGuard(jsUrl)) continue;
      await ctx.rate.acquire(host);
      const res = await httpProbe(jsUrl, { timeout: 10_000, rateLimiter: ctx.rate, host, maxBytes: 700_000 });
      const sha = crypto.createHash('sha256').update(res.body || '').digest('hex');
      const urlAsset = ctx.store.addAsset({ type: 'JS_RESOURCE', key: jsUrl.toLowerCase(), value: jsUrl });
      const evId = ctx.store.addEvidence({
        module_key: 'js_intel', asset_id: urlAsset, kind: 'JS_RESOURCE', source: `HTTP ${res.status || res.error} ${jsUrl}`,
        summary: res.ok ? `Fetched ${jsUrl} (${(res.body || '').length} bytes, sha256 ${sha.slice(0, 16)}…)` : `Unreachable: ${jsUrl} (${res.error})`,
        content: { url: jsUrl, status: res.status || null, bytes: (res.body || '').length, sha256: sha, body_excerpt: res.ok ? (res.body || '').slice(0, 40_000) : '' },
      });
      if (!res.ok) {
        run(`INSERT INTO js_resources (id, scan_id, asset_id, url, bytes, sha256, fetched_ok, evidence_id, meta, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
          [uid('jsr'), ctx.scan.id, urlAsset, jsUrl, 0, sha, 0, evId, '{}', now()]);
        continue;
      }
      fetched++;
      const jsId = uid('jsr');
      run(`INSERT INTO js_resources (id, scan_id, asset_id, url, bytes, sha256, fetched_ok, evidence_id, meta, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
        [jsId, ctx.scan.id, urlAsset, jsUrl, (res.body || '').length, sha, 1, evId, '{}', now()]);
      const body = res.body || '';
      // API routes: fetch/axios/xhr strings
      const routeMatches = new Set();
      for (const m of body.matchAll(/(?:fetch|axios(?:\.\w+)?|\.ajax|\.get|\.post|\.put|\.delete|\.open)\(\s*[`'"]([^`'"]{2,200})[`'"]/g)) routeMatches.add(m[1]);
      for (const m of body.matchAll(/["'](\/(?:api|v\d)\/[A-Za-z0-9_\-/.{}:]{1,120})["']/g)) routeMatches.add(m[1]);
      for (const m of body.matchAll(/baseURL\s*[:=]\s*["']([^"']+)["']/g)) routeMatches.add(`baseURL: ${m[1]}`);
      for (const route of [...routeMatches].slice(0, 80)) {
        const rEv = ctx.store.addEvidence({ module_key: 'js_intel', asset_id: urlAsset, kind: 'JS_ROUTE', source: `JS content of ${jsUrl}`, summary: `Route/API reference "${route.slice(0, 120)}" in ${jsUrl}`, content: { js: jsUrl, route, context: contextAround(body, route) } });
        run(`INSERT INTO js_routes (id, js_id, route, kind, context, evidence_id) VALUES (?,?,?,?,?,?)`, [uid('jrt'), jsId, route.slice(0, 200), classifyRoute(route), contextAround(body, route).slice(0, 200), rEv]);
        routes++;
      }
      // domains/subdomains
      const domainMatches = new Set();
      for (const m of body.matchAll(/https?:\/\/[a-zA-Z0-9._\-]+\.[a-zA-Z]{2,}(?:\/[^\s"'`<>]{0,80})?/g)) domainMatches.add(m[0]);
      for (const d of [...domainMatches].slice(0, 60)) {
        if (ctx.netGuard(d)) continue;
        const dEv = ctx.store.addEvidence({ module_key: 'js_intel', asset_id: urlAsset, kind: 'JS_DOMAIN_REF', source: `JS content of ${jsUrl}`, summary: `Domain/URL reference "${d.slice(0, 120)}" in ${jsUrl}`, content: { js: jsUrl, reference: d } });
        refs++;
      }
      // config refs / identifiers
      for (const m of [...body.matchAll(/(?:window\.__[A-Z_]+__|window\.config|process\.env\.[A-Z_]+)/g)].slice(0, 20)) {
        const cEv = ctx.store.addEvidence({ module_key: 'js_intel', asset_id: urlAsset, kind: 'JS_CONFIG_REF', source: `JS content of ${jsUrl}`, summary: `Configuration reference "${m[0]}" in ${jsUrl}`, content: { js: jsUrl, reference: m[0], context: contextAround(body, m[0]) } });
      }
      for (const m of [...body.matchAll(/(?:UA-[\d-]+|G-[A-Z0-9]{8,}|AIza[0-9A-Za-z\-_]{20,})/g)].slice(0, 10)) {
        const cEv = ctx.store.addEvidence({ module_key: 'js_intel', asset_id: urlAsset, kind: 'JS_PUBLIC_IDENTIFIER', source: `JS content of ${jsUrl}`, summary: `Public identifier "${redact(m[0])}" in ${jsUrl} (analytics/identifier — typically public)`, content: { js: jsUrl, redacted: redact(m[0]) } });
      }
      // secrets
      const secrets = scanForSecrets(body);
      secretsFound += recordSecrets(ctx, { jsId, pageUrl: jsUrl, secrets, inline: false });
    }
    return {
      status: (fetched || routes || secretsFound) ? 'COMPLETED' : 'COMPLETED_NO_RESULTS',
      detail: { js_fetched: fetched, routes, secrets: secretsFound, note: 'Potential secrets are UNVERIFIED pattern matches with redacted evidence. They require human verification before any exposure conclusion.' },
    };
  },
};

function classifyRoute(route) {
  const r = route.toLowerCase();
  if (/login|auth|token|session|signin/.test(r)) return 'AUTHENTICATION';
  if (/admin|internal/.test(r)) return 'ADMIN';
  if (/upload|file/.test(r)) return 'UPLOAD';
  if (r.startsWith('baseurl:')) return 'CONFIG';
  return 'API';
}
function contextAround(body, needle, span = 100) {
  const i = body.indexOf(needle);
  if (i < 0) return '';
  return body.slice(Math.max(0, i - span), i + needle.length + span).replace(/\s+/g, ' ');
}
function scanForSecrets(body) {
  const found = [];
  for (const p of SECRET_PATTERNS) {
    for (const m of body.matchAll(p.re)) {
      found.push({ kind: p.kind, match: m[0], confidence: p.confidence, severity: p.sev, context: contextAround(body, m[0]) });
      if (found.length > 40) return found;
    }
  }
  return found;
}
function recordSecrets(ctx, { jsId, pageUrl, secrets, inline }) {
  let n = 0;
  for (const s of secrets) {
    const evId = ctx.store.addEvidence({
      module_key: 'js_intel', kind: 'JS_POTENTIAL_SECRET', source: inline ? `Inline script of ${pageUrl}` : `JS content of ${pageUrl}`,
      summary: `Potential ${s.kind} in ${inline ? 'inline script' : 'JavaScript'} (${s.confidence} confidence) — REDACTED: ${redact(s.match)}`,
      content: { location: inline ? `inline:${pageUrl}` : pageUrl, kind: s.kind, redacted_match: redact(s.match), length: s.match.length, context: s.context.slice(0, 300), verification: 'UNVERIFIED', note: 'Regex-based pattern match. Verification by a human analyst is required before any exposure conclusion. Full value is NOT stored.' },
    });
    if (jsId) {
      run(`INSERT INTO js_secrets (id, js_id, kind, match_redacted, verified, dismissed, context, confidence, evidence_id) VALUES (?,?,?,?,0,0,?,?,?)`,
        [uid('jsc'), jsId, s.kind, redact(s.match), s.context.slice(0, 250), s.confidence, evId]);
    }
    ctx.store.bump('js_intel');
    n++;
  }
  return n;
}

/* ---------------- Cloud intelligence ---------------- */
const CLOUD_SIGS = [
  { provider: 'AWS S3 bucket', re: /s3[.-]amazonaws\.com|s3:\/\/|[a-z0-9.-]+\.s3\.[a-z0-9-]+\.amazonaws\.com/i, conf: 'HIGH' },
  { provider: 'AWS', re: /amazonaws\.com|aws\.amazon\.com|x-amz-/i, conf: 'MEDIUM' },
  { provider: 'Azure', re: /azurewebsites\.net|blob\.core\.windows\.net|x-ms-request-id|azure\.microsoft/i, conf: 'MEDIUM' },
  { provider: 'Google Cloud', re: /storage\.googleapis\.com|appspot\.com|googleapis\.com|x-goog-/i, conf: 'MEDIUM' },
  { provider: 'DigitalOcean', re: /digitaloceanspaces\.com|digitalocean\.com/i, conf: 'MEDIUM' },
  { provider: 'Cloudflare Workers/Pages', re: /workers\.dev|pages\.dev/i, conf: 'MEDIUM' },
];

export const cloudIntel = {
  key: 'cloud_intel', name: 'Cloud / Hosting Intelligence', description: 'Identifies cloud & hosting signals strictly where evidence exists in responses (headers, body, redirect targets).',
  timeoutMs: 45_000,
  when: (ctx) => obs(ctx).length > 0,
  whenReason: 'No HTTP observations from which to derive cloud intelligence.',
  async run(ctx) {
    const rows = obs(ctx);
    let detected = 0;
    for (const row of rows) {
      const o = parseObs(row);
      const H = lower(o.headers);
      const haystack = [JSON.stringify(H).slice(0, 20_000), (o.body || '').slice(0, 30_000), (o.redirect_chain || []).map(c => c.location).join(' ')].join(' ');
      for (const sig of CLOUD_SIGS) {
        const m = haystack.match(sig.re);
        if (!m) continue;
        const cId = ctx.store.addAsset({ type: 'CLOUD', key: `cloud:${sig.provider}`.toLowerCase(), value: sig.provider, confidence: sig.conf });
        const urlAsset = ctx.store.addAsset({ type: 'URL', key: (o.final_url || o.url).toLowerCase(), value: o.final_url || o.url });
        const evId = ctx.store.addEvidence({
          module_key: 'cloud_intel', asset_id: cId, kind: 'CLOUD_SIGNAL', source: `Response evidence at ${o.url}`,
          summary: `Cloud signal "${sig.provider}" matched "${m[0].slice(0, 80)}" in evidence from ${o.url}`,
          content: { url: o.url, provider: sig.provider, match: m[0].slice(0, 200), confidence: sig.conf },
        });
        run(`INSERT INTO perimeter (id, scan_id, asset_id, kind, name, detection_method, raw_match, confidence, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
          [uid('per'), ctx.scan.id, cId, 'HOSTING', sig.provider, 'content/header signature', m[0].slice(0, 200), sig.conf, evId, now()]);
        ctx.store.addEdge(urlAsset, cId, 'HOSTED_ON');
        detected++;
        break; // one signal per URL is enough; avoid noise
      }
    }
    return { status: detected ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { detected, note: detected ? null : 'No cloud/hosting signatures matched collected evidence. No conclusion about hosting provider absence is implied.' } };
  },
};

/* ---------------- Screenshot (honest stub: requires renderer) ---------------- */
export const screenshotModule = {
  key: 'screenshot', name: 'Web Screenshots', description: 'Captures page screenshots when enabled and a rendering backend is configured.',
  timeoutMs: 30_000,
  async run(ctx) {
    const enabled = !!ctx.cfg.screenshots;
    if (!enabled) return { status: 'SKIPPED', detail: { reason: 'Screenshots not enabled in scan configuration.' } };
    return { status: 'SKIPPED', detail: { reason: 'No headless rendering backend is configured in this deployment. Screenshots were not captured — this limitation is recorded rather than silently ignored.' } };
  },
};

export const webModules = [techFingerprint, wafCdnDetect, securityPosture, robotsSitemap, endpointDiscovery, jsIntel, cloudIntel, screenshotModule];
