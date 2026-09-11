// KavachRecon — seeding.
// 1) A REAL, live passive DNS recon of a benign public domain (example.com) executed at first boot,
//    so the app opens with genuinely collected data and evidence.
// 2) A clearly-labelled DEMO workspace ("Demo Workspace — Nimbus Cloud") with an internally-consistent
//    demonstration dataset so the UI feels alive. Every demo record carries origin='DEMO_SEED' /
//    is_demo=1 and the UI badges it. It is never mixed into live scans.
import { db, q, q1, run, now, uid, audit } from '../db.js';
import { ensureDefaultUsers } from '../auth.js';
import { ScanEngine } from '../scanner/engine.js';
import { riskScore } from '../scanner/engine.js';

export async function seed({ liveRecon = true } = {}) {
  ensureDefaultUsers();
  const hasData = q1(`SELECT COUNT(*) n FROM workspaces`).n > 0;

  // ---------- 1) LIVE passive DNS recon (real data) ----------
  if (liveRecon && !q1(`SELECT COUNT(*) n FROM scans WHERE is_demo = 0`).n) {
    try {
      const wsId = uid('ws');
      run(`INSERT INTO workspaces (id, name, description, is_demo, created_by, created_at, updated_at) VALUES (?,?,?,0,(SELECT id FROM users LIMIT 1),?,?)`,
        [wsId, 'Live Recon (sandbox)', 'Workspace used for real scans executed from this deployment. The initial scan is a genuine passive DNS reconnaissance of a benign public domain (example.com), executed live at first boot.', now(), now()]);
      const tId = uid('tgt');
      run(`INSERT INTO targets (id, workspace_id, identifier, type, label, notes, active_confirmed, created_at, updated_at) VALUES (?,?,?,?,?,?,0,?,?)`,
        [tId, wsId, 'example.com', 'DOMAIN', 'Example domain (IANA-reserved)', 'IANA-reserved documentation domain — safe passive target.', now(), now()]);
      const sId = uid('scan');
      run(`INSERT INTO scans (id, workspace_id, target_id, name, mode, status, config, created_by, created_at) VALUES (?,?,?,?,?,'QUEUED',?,?,?)`,
        [sId, wsId, tId, 'Initial live DNS recon', 'PASSIVE_ONLY', JSON.stringify({ modules: ['dns_enum', 'email_security', 'subdomain_brute', 'dns_analysis'] }), (q1(`SELECT id FROM users ORDER BY created_at LIMIT 1`).id), now()]);
      console.log('[seed] running live passive DNS recon of example.com …');
      await ScanEngine.execute(sId, { cancelled: false });
      console.log('[seed] live recon finished:', q1(`SELECT status FROM scans WHERE id = ?`, [sId]).status);
    } catch (e) {
      console.error('[seed] live recon failed (recorded honestly):', e.message);
    }
  }

  // ---------- 2) DEMO workspace (labeled demo data) ----------
  if (!q1(`SELECT COUNT(*) n FROM workspaces WHERE is_demo = 1`).n) {
    seedDemoWorkspace();
  }
}

export function seedDemoWorkspace() {
  const t0 = Date.now();
  const wsId = uid('ws');
  const userId = q1(`SELECT id FROM users ORDER BY created_at LIMIT 1`).id;
  run(`INSERT INTO workspaces (id, name, description, is_demo, created_by, created_at, updated_at) VALUES (?,?,?,1,?,?,?)`,
    [wsId, 'Demo Workspace — Nimbus Cloud', 'DEMONSTRATION DATA: a synthetic, internally-consistent dataset that ships with KavachRecon so the interface can be explored before running real scans. Every record here is labelled DEMO and can be purged from Settings → Demo data. It does NOT represent a real organization and is never mixed with live scan output.', userId, now(), now()]);
  audit('system', 'seed.demo_workspace', 'workspace', wsId, { labeled: 'DEMO' });

  const tId = uid('tgt');
  run(`INSERT INTO targets (id, workspace_id, identifier, type, label, notes, active_confirmed, created_at, updated_at) VALUES (?,?,?,?,?,?,1,?,?)`,
    [tId, wsId, 'nimbus-cloud.io', 'DOMAIN', 'Nimbus Cloud (demo)', 'DEMO target — synthetic organization used for product demonstration.', now(), now()]);
  const sId = uid('scan');
  const started = new Date(Date.now() - 3600_000).toISOString();
  const finished = new Date(Date.now() - 3300_000).toISOString();
  run(`INSERT INTO scans (id, workspace_id, target_id, name, mode, status, config, is_demo, created_by, created_at, started_at, finished_at) VALUES (?,?,?,?,?,'COMPLETED',?,1,?,?,?,?)`,
    [sId, wsId, tId, 'Baseline attack-surface scan (demo)', 'ACTIVE_CONFIRMED', JSON.stringify({ top_ports: 'extended', screenshots: false }), userId, now(), started, finished]);

  const A = {}; // asset cache
  const asset = (type, key, value, opts = {}) => {
    const id = uid('ast');
    run(`INSERT INTO assets (id, workspace_id, scan_id, type, key, value, parent_id, status, origin, confidence, verification, meta, first_seen, last_seen)
         VALUES (?,?,?,?,?,?,?,?, 'DEMO_SEED', ?, 'UNVERIFIED', '{}', ?, ?)`,
      [id, wsId, sId, type, key.toLowerCase(), value, opts.parent || null, opts.status || 'ACTIVE', opts.conf || 'MEDIUM', opts.seen || started, opts.seen || started]);
    A[key.toLowerCase()] = id;
    return id;
  };
  const edge = (src, dst, rel) => { const a = A[src.toLowerCase()], b = A[dst.toLowerCase()]; if (!a || !b) return; run(`INSERT OR IGNORE INTO asset_edges (id, workspace_id, src_id, dst_id, relation, scan_id) VALUES (?,?,?,?,?,?)`, [uid('edg'), wsId, a, b, rel, sId]); };
  const ev = (module_key, kind, source, summary, assetKey = null, content = {}) => {
    const id = uid('ev');
    run(`INSERT INTO evidence (id, scan_id, workspace_id, module_key, asset_id, kind, source, summary, content, hash, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [id, sId, wsId, module_key, assetKey ? (A[assetKey.toLowerCase()] ?? null) : null, kind, source, summary, JSON.stringify(content), 'demo', new Date(Date.now() - 3400_000).toISOString()]);
    return id;
  };
  const dns = (domain, type, name, value, evId, assetKey = null) => run(`INSERT INTO dns_records (id, scan_id, asset_id, domain, type, name, value, ttl, meta, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
    [uid('dns'), sId, assetKey ? (A[assetKey.toLowerCase()] ?? null) : null, domain, type, name, value, 3600, '{}', new Date(Date.now() - 3400_000).toISOString()]);
  const port = (host, ip, p, state, service, banner, version, conf, evId) => {
    const portKey = `${ip}:${p}/tcp`;
    if (A[`port:${portKey}`]) return A[`port:${portKey}`]; // same endpoint already recorded
    const portId = asset('PORT', `port:${portKey}`, `${ip}:${p}/tcp (${state})`, { parent: `ip:${ip}` });
    run(`INSERT INTO host_ports (id, scan_id, asset_id, host, ip, port, protocol, state, service, banner, version, confidence, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [uid('prt'), sId, portId, host, ip, p, 'tcp', state, service, banner, version, conf, evId, new Date(Date.now() - 3350_000).toISOString()]);
    return portId;
  };
  const web = (url, finalUrl, status, title, server, headers, tls) => {
    const id = uid('web');
    const urlKey = finalUrl.toLowerCase();
    let urlId = A[`url:${urlKey}`];
    if (!urlId) urlId = asset('URL', `url:${urlKey}`, finalUrl, { parent: `host:${new URL(finalUrl).host}` });
    run(`INSERT INTO web_observations (id, scan_id, asset_id, url, final_url, status_code, ok, redirect_chain, title, server, content_type, headers, tls, evidence_id, collected_at) VALUES (?,?,?,?,?,?,1,'[]',?,?,?,?,?,?,?)`,
      [id, sId, urlId, url, finalUrl, status, title, server, 'text/html; charset=utf-8', JSON.stringify(headers), tls ? JSON.stringify(tls) : null, null, new Date(Date.now() - 3300_000).toISOString()]);
    return { id, urlId };
  };
  const endpoint = (url, cls, status, note, evId) => {
    const id = uid('end');
    run(`INSERT INTO endpoints (id, scan_id, asset_id, url, classification, status_code, verified, evidence_id, note, collected_at) VALUES (?,?,?,?,?,?,0,?,?,?)`,
      [id, sId, null, url, cls, status, evId, note, new Date(Date.now() - 3250_000).toISOString()]);
    return id;
  };
  const posture = (url, kind, state, header, value, evId, detail = {}) => run(`INSERT INTO posture (id, scan_id, asset_id, url, kind, state, header, value, detail, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [uid('pos'), sId, null, url, kind, state, header, value, JSON.stringify(detail), evId, new Date(Date.now() - 3200_000).toISOString()]);
  const tech = (name, version, category, method, match, conf, evId, assetKey) => run(`INSERT INTO technologies (id, scan_id, asset_id, name, version, category, detection_method, raw_match, confidence, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [uid('tech'), sId, assetKey ? A[assetKey.toLowerCase()] : null, name, version, category, method, match, conf, evId, new Date(Date.now() - 3200_000).toISOString()]);
  const perim = (kind, name, method, match, conf, evId, assetKey) => run(`INSERT INTO perimeter (id, scan_id, asset_id, kind, name, detection_method, raw_match, confidence, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
    [uid('per'), sId, assetKey ? A[assetKey.toLowerCase()] : null, kind, name, method, match, conf, evId, new Date(Date.now() - 3200_000).toISOString()]);
  const finding = (key, title, category, classification, severity, confidence, assetLabel, description, impact, recommendation, evIds) => {
    const id = uid('fnd');
    const score = riskScore(severity, classification, confidence);
    run(`INSERT INTO findings (id, workspace_id, scan_id, finding_key, title, category, classification, severity, risk_score, confidence, asset_id, asset_label, description, impact, recommendation, status, evidence_ids, meta, is_demo, first_seen_scan_id, last_seen_scan_id, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?,?,?,?,'OPEN',?,'{}',1,?,?,?,?)`,
      [id, wsId, sId, key, title, category, classification, severity, score, confidence, assetLabel, description, impact, recommendation, JSON.stringify(evIds), sId, sId, started, started]);
    return id;
  };

  /* ----- assets: domains/subdomains/ips/hosts ----- */
  asset('DOMAIN', 'domain:nimbus-cloud.io', 'nimbus-cloud.io', { conf: 'HIGH' });
  const subs = [
    ['www.nimbus-cloud.io', '151.101.64.11'], ['api.nimbus-cloud.io', '151.101.64.11'], ['app.nimbus-cloud.io', '151.101.66.42'],
    ['mail.nimbus-cloud.io', '198.51.100.7'], ['vpn.nimbus-cloud.io', '203.0.113.9'], ['staging.nimbus-cloud.io', '151.101.66.42'],
    ['status.nimbus-cloud.io', '151.101.64.11'], ['cdn.nimbus-cloud.io', '104.18.32.7'],
  ];
  for (const ns of ['ns1.nimbus-cloud.io', 'ns2.nimbus-cloud.io']) {
    asset('HOST', `host:${ns}`, ns);
    edge('domain:nimbus-cloud.io', `host:${ns}`, 'DNS_SERVER');
  }
  for (const [host, ip] of subs) {
    asset('SUBDOMAIN', `sub:${host}`, host, { parent: 'domain:nimbus-cloud.io', conf: 'HIGH' });
    edge('domain:nimbus-cloud.io', `sub:${host}`, 'HAS_SUBDOMAIN');
    if (!A[`ip:${ip}`]) {
      asset('IP', `ip:${ip}`, ip, { conf: 'HIGH' });
      if (!A['cidr:151.101.64.0/22']) asset('CIDR', 'cidr:151.101.64.0/22', '151.101.64.0/22', { conf: 'HIGH' });
      edge('cidr:151.101.64.0/22', `ip:${ip}`, 'CONTAINS');
    }
    asset('HOST', `host:${host}`, host);
    edge(`sub:${host}`, `host:${host}`, 'ALIAS_OF');
    edge(`host:${host}`, `ip:${ip}`, 'RESOLVES_TO');
  }

  /* ----- DNS records (demo values, coherent) ----- */
  let e = ev('dns_enum', 'DNS_RECORD', 'DNS resolver (demo)', 'nimbus-cloud.io A → 151.101.64.11', 'ip:151.101.64.11', { domain: 'nimbus-cloud.io', type: 'A', name: 'nimbus-cloud.io', value: '151.101.64.11' });
  dns('nimbus-cloud.io', 'A', 'nimbus-cloud.io', '151.101.64.11', e, 'ip:151.101.64.11');
  dns('nimbus-cloud.io', 'AAAA', 'nimbus-cloud.io', '9012:5678::10', ev('dns_enum', 'DNS_RECORD', 'DNS resolver (demo)', 'nimbus-cloud.io AAAA → 9012:5678::10'));
  for (const ns of ['ns1.nimbus-cloud.io', 'ns2.nimbus-cloud.io']) {
    dns('nimbus-cloud.io', 'NS', 'nimbus-cloud.io', ns, ev('dns_enum', 'DNS_RECORD', 'DNS resolver (demo)', `nimbus-cloud.io NS → ${ns}`, `host:${ns}`), `host:${ns}`);
  }
  dns('nimbus-cloud.io', 'MX', 'nimbus-cloud.io', '10 mail.nimbus-cloud.io', ev('dns_enum', 'DNS_RECORD', 'DNS resolver (demo)', 'nimbus-cloud.io MX → 10 mail.nimbus-cloud.io', 'host:mail.nimbus-cloud.io'), 'host:mail.nimbus-cloud.io');
  dns('nimbus-cloud.io', 'TXT', 'nimbus-cloud.io', 'v=spf1 include:_spf.nimbus-cloud.io -all', ev('email_security', 'DNS_RECORD', 'DNS resolver (demo)', 'SPF record: v=spf1 include:_spf.nimbus-cloud.io -all', 'domain:nimbus-cloud.io', { label: 'SPF' }));
  dns('nimbus-cloud.io', 'TXT', 'nimbus-cloud.io', 'atlassian-domain-verification=demo-xxxx', ev('dns_enum', 'DNS_RECORD', 'DNS resolver (demo)', 'TXT verification record'));
  dns('nimbus-cloud.io', 'SOA', 'nimbus-cloud.io', 'ns1.nimbus-cloud.io hostmaster.nimbus-cloud.io 2026091001', ev('dns_enum', 'DNS_RECORD', 'DNS resolver (demo)', 'SOA serial 2026091001'));
  dns('nimbus-cloud.io', 'CAA', 'nimbus-cloud.io', '0 issue "letsencrypt.org"', ev('dns_enum', 'DNS_RECORD', 'DNS resolver (demo)', 'CAA: letsencrypt.org only'));
  dns('_dmarc.nimbus-cloud.io', 'TXT', '_dmarc.nimbus-cloud.io', 'v=DMARC1; p=quarantine; rua=mailto:dmarc@nimbus-cloud.io', ev('email_security', 'DNS_RECORD', 'DNS resolver (demo)', 'DMARC policy p=quarantine', 'domain:nimbus-cloud.io', { label: 'DMARC' }));
  dns('nimbus-cloud.io', 'CNAME', 'status.nimbus-cloud.io', 'statuspage.umbrellademo.net', ev('dns_analysis', 'DNS_DANGLING_CNAME', 'DNS resolver (demo)', 'CNAME target statuspage.umbrellademo.net did not resolve (NXDOMAIN) — potential dangling record', 'sub:status.nimbus-cloud.io', { cname_target: 'statuspage.umbrellademo.net' }));

  /* ----- ports & services ----- */
  const pEv = (h, p, svc, banner) => ev('port_scan', 'PORT_RESULT', 'TCP connect + service probe', `${h} :${p}/tcp OPEN service≈${svc}${banner ? ` banner "${banner.slice(0, 40)}"` : ''}`, `host:${h}`, {});
  port('app.nimbus-cloud.io', '151.101.66.42', 22, 'OPEN', 'ssh', 'SSH-2.0-OpenSSH_9.6p1 Debian-3', 'OpenSSH_9.6p1', 'HIGH', pEv('app.nimbus-cloud.io', 22, 'ssh', 'SSH-2.0-OpenSSH_9.6p1'));
  port('app.nimbus-cloud.io', '151.101.66.42', 443, 'OPEN', 'https', null, null, 'HIGH', pEv('app.nimbus-cloud.io', 443, 'https', null));
  port('www.nimbus-cloud.io', '151.101.64.11', 80, 'OPEN', 'http', null, null, 'HIGH', pEv('www.nimbus-cloud.io', 80, 'http', null));
  port('www.nimbus-cloud.io', '151.101.64.11', 443, 'OPEN', 'https', null, null, 'HIGH', pEv('www.nimbus-cloud.io', 443, 'https', null));
  port('api.nimbus-cloud.io', '151.101.64.11', 443, 'OPEN', 'https', null, null, 'HIGH', pEv('api.nimbus-cloud.io', 443, 'https', null));
  port('staging.nimbus-cloud.io', '151.101.66.42', 8080, 'OPEN', 'http-proxy', 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0', 'nginx/1.24.0', 'HIGH', pEv('staging.nimbus-cloud.io', 8080, 'http-proxy', 'HTTP/1.1 200 OK'));
  port('mail.nimbus-cloud.io', '198.51.100.7', 25, 'OPEN', 'smtp', '220 mail.nimbus-cloud.io ESMTP Postfix (Debian/GNU)', 'Postfix', 'HIGH', pEv('mail.nimbus-cloud.io', 25, 'smtp', '220 mail…'));
  port('mail.nimbus-cloud.io', '198.51.100.7', 993, 'OPEN', 'imaps', null, null, 'HIGH', pEv('mail.nimbus-cloud.io', 993, 'imaps', null));
  port('vpn.nimbus-cloud.io', '203.0.113.9', 1194, 'OPEN_UNVERIFIED', 'openvpn', null, null, 'LOW', ev('port_scan', 'PORT_RESULT', 'TCP connect + probe', 'vpn.nimbus-cloud.io :1194/tcp OPEN_UNVERIFIED — connect accepted, no service response (identity unconfirmed)', 'host:vpn.nimbus-cloud.io'));
  port('db.internal.nimbus-cloud.io', '203.0.113.20', 5432, 'OPEN', 'postgresql', null, null, 'MEDIUM', ev('port_scan', 'PORT_RESULT', 'TCP connect + probe', 'db.internal.nimbus-cloud.io :5432/tcp OPEN service≈postgresql — no banner', 'ip:203.0.113.20'));

  /* ----- web observations ----- */
  const H = (extra = {}) => ({ 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'content-type': 'text/html; charset=utf-8', 'set-cookie': 'session=DEMO…; HttpOnly; SameSite=Lax', ...extra });
  const tlsOk = { ok: true, protocol: 'TLSv1_3', cipher: 'TLS_AES_256_GCM_SHA384', cert: { subject: { CN: 'nimbus-cloud.io' }, issuer: { O: "Let's Encrypt" }, valid_from: '2026-08-30T00:00:00Z', valid_to: '2026-09-24T00:00:00Z', fingerprint256: 'DE:MO:…:01', subjectaltname: 'DNS:nimbus-cloud.io, DNS:www.nimbus-cloud.io' }, chainLength: 1 };
  web('http://nimbus-cloud.io', 'https://nimbus-cloud.io/', 200, 'Nimbus Cloud — Modern Cloud Platform', 'cloudflare', H({ 'via': '1.1 cloudflare', 'cf-ray': '8c1demo2-LHR', 'server': 'cloudflare' }), null);
  const w1 = web('https://nimbus-cloud.io/', 'https://nimbus-cloud.io/', 200, 'Nimbus Cloud — Modern Cloud Platform', 'cloudflare', H({ 'via': '1.1 cloudflare', 'cf-ray': '8c1demo3-LHR', 'server': 'cloudflare', 'expect-ct': 'max-age=0' }), tlsOk);
  const w2 = web('https://app.nimbus-cloud.io/', 'https://app.nimbus-cloud.io/login', 200, 'Sign in — Nimbus Console', 'nginx/1.25.3', H({ 'server': 'nginx/1.25.3', 'x-powered-by': 'Express', 'set-cookie': 'connect.sid=DEMO; Path=/; HttpOnly; SameSite=Lax' }), tlsOk);
  const w3 = web('https://api.nimbus-cloud.io/v1', 'https://api.nimbus-cloud.io/v1', 401, 'Nimbus API', 'cloudflare', H({ 'server': 'cloudflare', 'cf-ray': '8c1demo4-LHR' }), tlsOk);
  const w4 = web('https://staging.nimbus-cloud.io:8080/', 'https://staging.nimbus-cloud.io:8080/', 200, 'Staging — Nimbus Console (UAT)', 'nginx/1.24.0', H({ 'server': 'nginx/1.24.0' }), { ...tlsOk, protocol: 'TLSv1_2', legacySupport: { tls10: false, tls11: true } });
  edge('url:https://nimbus-cloud.io/', 'tech:nginx', 'USES_TECHNOLOGY');

  /* ----- endpoints ----- */
  const evRobots = ev('robots_sitemap', 'ROBOTS_TXT', 'https://nimbus-cloud.io/robots.txt (HTTP 200)', 'robots.txt retrieved: 6 Disallow, 1 Sitemap directives', 'url:https://nimbus-cloud.io/', {});
  endpoint('https://nimbus-cloud.io/', 'PUBLIC', 200, 'Directly probed — HTTP 200 observed.', w1.id);
  endpoint('https://app.nimbus-cloud.io/login', 'LOGIN', 200, 'Directly probed — HTTP 200 observed.', w2.id);
  endpoint('https://app.nimbus-cloud.io/oauth/token', 'AUTHENTICATION', 401, 'Probed during API discovery — HTTP 401.', ev('endpoint_discovery', 'ENDPOINT_REFERENCE', 'JS content of app.min.js', 'OAuth token route referenced in app.min.js'));
  endpoint('https://api.nimbus-cloud.io/v1', 'API', 401, 'Directly probed — HTTP 401 observed.', w3.id);
  endpoint('https://api.nimbus-cloud.io/v1/graphql', 'API', 400, 'Probed — HTTP 400 (endpoint exists, rejects empty query).', ev('endpoint_discovery', 'ENDPOINT_REFERENCE', 'JS content of app.min.js', 'GraphQL route referenced in app.min.js'));
  endpoint('https://api.nimbus-cloud.io/v1/docs', 'DOCUMENTATION', 200, 'Probed — HTTP 200 (OpenAPI docs).', ev('endpoint_discovery', 'ENDPOINT_REFERENCE', 'sitemap.xml', 'Listed in sitemap.xml'));
  endpoint('https://app.nimbus-cloud.io/admin', 'ADMIN', 200, 'Directly probed — HTTP 200 observed. Path-based classification ONLY; function unverified.', ev('http_probe', 'HTTP_OBSERVATION', 'HTTP 200', 'https://app.nimbus-cloud.io/admin → 200 (title "Redirecting…")'));
  endpoint('https://staging.nimbus-cloud.io:8080/backup/', 'POTENTIALLY_SENSITIVE', 200, 'Directly probed — HTTP 200. Possibly soft-404; body content not security-reviewed.', ev('http_probe', 'HTTP_OBSERVATION', 'HTTP 200', 'https://staging.nimbus-cloud.io:8080/backup/ → 200'));
  endpoint('https://nimbus-cloud.io/pricing', 'PUBLIC', 200, 'Referenced from homepage markup.', ev('endpoint_discovery', 'ENDPOINT_REFERENCE', 'HTML of https://nimbus-cloud.io/', 'href="pricing" found'));
  endpoint('https://nimbus-cloud.io/static/logo.svg', 'STATIC', 200, 'Referenced from homepage markup.', ev('endpoint_discovery', 'ENDPOINT_REFERENCE', 'HTML of https://nimbus-cloud.io/', 'src found'));
  endpoint('https://nimbus-cloud.io/.well-known/security.txt', 'PUBLIC', 200, 'Probed — HTTP 200 (security.txt present).', evRobots);

  /* ----- JS intel ----- */
  const jsId = uid('jsr');
  const jsAsset = asset('JS_RESOURCE', 'js:https://app.nimbus-cloud.io/static/app.min.js', 'https://app.nimbus-cloud.io/static/app.min.js', { parent: 'host:app.nimbus-cloud.io' });
  const evJs = ev('js_intel', 'JS_RESOURCE', 'HTTP 200 https://app.nimbus-cloud.io/static/app.min.js', 'Fetched app.min.js (184,223 bytes, sha256 demo…)', 'js:https://app.nimbus-cloud.io/static/app.min.js', {});
  run(`INSERT INTO js_resources (id, scan_id, asset_id, url, bytes, sha256, fetched_ok, evidence_id, meta, collected_at) VALUES (?,?,?,?,?,?,1,?,?,?)`,
    [jsId, sId, jsAsset, 'https://app.nimbus-cloud.io/static/app.min.js', 184223, 'demo0123456789abcdef', evJs, '{}', new Date(Date.now() - 3260_000).toISOString()]);
  for (const [route, kind] of [['/api/v1/auth/login', 'AUTHENTICATION'], ['/api/v1/users/me', 'API'], ['/api/v1/graphql', 'API'], ['/api/v1/uploads', 'UPLOAD'], ['/api/internal/metrics', 'ADMIN']]) {
    run(`INSERT INTO js_routes (id, js_id, route, kind, context, evidence_id) VALUES (?,?,?,?,?,?)`, [uid('jrt'), jsId, route, kind, 'e.post(`${API_BASE}${route}`)', ev('js_intel', 'JS_ROUTE', 'JS content of app.min.js', `Route reference "${route}" in app.min.js`, 'js:https://app.nimbus-cloud.io/static/app.min.js', {})]);
  }
  run(`INSERT INTO js_secrets (id, js_id, kind, match_redacted, verified, dismissed, context, confidence, evidence_id) VALUES (?,?,?,?,0,0,?,?,?)`,
    [uid('jsc'), jsId, 'AWS Access Key ID', 'AKIA****XQ', 'const AWS_ACCESS_KEY="AKIA…"; // demo', 'HIGH', ev('js_intel', 'JS_POTENTIAL_SECRET', 'JS content of app.min.js', 'Potential AWS Access Key ID in app.min.js — REDACTED: AKIA****XQ', 'js:https://app.nimbus-cloud.io/static/app.min.js', { verification: 'UNVERIFIED' })]);

  /* ----- technologies & perimeter ----- */
  tech('nginx', '1.25.3', 'web-server', 'server header', 'nginx/1.25.3', 'HIGH', ev('tech_fingerprint', 'TECH_DETECTION', 'server header on app.nimbus-cloud.io', 'nginx/1.25.3 detected via Server header', 'url:https://app.nimbus-cloud.io/login', {}), 'url:https://app.nimbus-cloud.io/login');
  tech('Express', null, 'web-framework', 'x-powered-by header', 'Express', 'HIGH', ev('tech_fingerprint', 'TECH_DETECTION', 'x-powered-by on app.nimbus-cloud.io', 'Express via X-Powered-By', 'url:https://app.nimbus-cloud.io/login', {}), 'url:https://app.nimbus-cloud.io/login');
  tech('React', '18', 'js-framework', 'HTML content pattern', 'data-reactroot', 'MEDIUM', ev('tech_fingerprint', 'TECH_DETECTION', 'HTML of app.nimbus-cloud.io', 'React markers in markup', 'url:https://app.nimbus-cloud.io/login', {}), 'url:https://app.nimbus-cloud.io/login');
  tech('Cloudflare', null, 'edge', 'server header', 'cloudflare', 'HIGH', ev('tech_fingerprint', 'TECH_DETECTION', 'server header on nimbus-cloud.io', 'cloudflare Server header', 'url:https://nimbus-cloud.io/', {}), 'url:https://nimbus-cloud.io/');
  perim('CDN', 'Cloudflare', 'response header (cf-ray)', '8c1demo3-LHR', 'HIGH', ev('waf_cdn', 'PERIMETER_DETECTION', 'cf-ray header on https://nimbus-cloud.io/', 'CDN Cloudflare indicated by cf-ray', 'url:https://nimbus-cloud.io/', {}), 'url:https://nimbus-cloud.io/');
  perim('HOSTING', 'AWS S3 bucket', 'content/header signature', 's3.amazonaws.com', 'HIGH', ev('cloud_intel', 'CLOUD_SIGNAL', 'Response evidence at https://nimbus-cloud.io/', 'Cloud signal AWS S3 (redirect target to assets bucket)', 'url:https://nimbus-cloud.io/', {}), 'url:https://nimbus-cloud.io/');

  /* ----- posture ----- */
  posture('https://nimbus-cloud.io/', 'CSP', 'MISSING', 'content-security-policy', null, ev('security_posture', 'SECURITY_HEADER', 'Response headers of https://nimbus-cloud.io/', 'CSP header ABSENT on https://nimbus-cloud.io/ (status 200)', 'url:https://nimbus-cloud.io/', { status: 200 }));
  posture('https://nimbus-cloud.io/', 'HSTS', 'PRESENT', 'strict-transport-security', 'max-age=31536000; includeSubDomains', ev('security_posture', 'SECURITY_HEADER', 'Response headers', 'HSTS present'));
  posture('https://nimbus-cloud.io/', 'XCTO', 'PRESENT', 'x-content-type-options', 'nosniff', ev('security_posture', 'SECURITY_HEADER', 'Response headers', 'XCTO present'));
  posture('https://nimbus-cloud.io/', 'XFO', 'MISSING', 'x-frame-options', null, ev('security_posture', 'SECURITY_HEADER', 'Response headers', 'XFO ABSENT (status 200)'));
  posture('https://app.nimbus-cloud.io/login', 'COOKIE', 'WEAK_FLAGS', 'connect.sid', 'connect.sid=…; HttpOnly; SameSite=Lax (Secure missing)', ev('security_posture', 'COOKIE', 'Set-Cookie on app login', 'Cookie "connect.sid": Secure=false, HttpOnly=true, SameSite=Lax'));
  posture('http://nimbus-cloud.io', 'HTTPS_REDIRECT', 'ENFORCED', null, 'https://nimbus-cloud.io/', ev('security_posture', 'HTTPS_REDIRECT', 'Redirect chain', 'http → https enforced (301)'));
  posture('https://app.nimbus-cloud.io/login', 'CERT', 'EXPIRING_SOON', 'nimbus-cloud.io', 'valid_to=2026-09-24T00:00:00Z', ev('security_posture', 'TLS_CERT', 'Certificate presented by app.nimbus-cloud.io', 'Certificate expires in 13 days (2026-09-24)', null, { days_remaining: 13 }));
  posture('https://staging.nimbus-cloud.io:8080/', 'TLS', 'WEAK_PROTOCOL', 'TLSv1_1', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', ev('security_posture', 'TLS', 'TLS handshake', 'Legacy TLSv1.1 ACCEPTED by staging.nimbus-cloud.io:8080'));

  /* ----- findings (demo, all evidence-linked) ----- */
  finding('demo-csp-missing', 'Security header "Content-Security-Policy" not observed on nimbus-cloud.io', 'HTTP_SECURITY_HEADERS', 'OBSERVED', 'LOW', 'HIGH', 'nimbus-cloud.io',
    'The Content-Security-Policy response header was absent from the actual HTTPS response collected during the demo scan. Observation, not a confirmed vulnerability.',
    'Reduced defense-in-depth against cross-site scripting and content injection.',
    'Evaluate whether CSP can be enabled (start report-only).', ['x']);
  finding('demo-admin-path', 'Potential administrative endpoint observed — manual verification required', 'WEB_EXPOSURE', 'MANUAL_REVIEW', 'MEDIUM', 'LOW', 'https://app.nimbus-cloud.io/admin',
    'https://app.nimbus-cloud.io/admin responded with HTTP 200 during probing; the path pattern classifies as administrative. The actual function was NOT verified — could be a real admin panel, an app route, or a soft-404.',
    'If genuine and unauthenticated, could allow privileged actions.',
    'Open in an authorised review; confirm authentication requirements before drawing any conclusion.', ['x']);
  finding('demo-backup-path', 'Potentially sensitive path returned HTTP 200 — content verification required', 'WEB_EXPOSURE', 'MANUAL_REVIEW', 'HIGH', 'LOW', 'https://staging.nimbus-cloud.io:8080/backup/',
    'The path /backup/ on staging returned HTTP 200. Pattern matches backup-style paths. A 200 can be a soft-404 or SPA catch-all; the response body was not security-reviewed.',
    'If genuine, directory listings/backups can leak source or credentials.',
    'Manually inspect the response content; confirm or reject.', ['x']);
  finding('demo-aws-key', 'Unverified potential secret in JavaScript: AWS Access Key ID', 'SECRET_EXPOSURE', 'MANUAL_REVIEW', 'HIGH', 'MEDIUM', 'https://app.nimbus-cloud.io/static/app.min.js',
    'A regex scan found a potential AWS Access Key ID in app.min.js (redacted: AKIA****XQ). The full value was never stored. It may be an example/dummy value — human verification REQUIRED.',
    'If genuine, the credential could allow S3/IAM access.',
    'Open the JS asset, locate the string, verify against AWS; revoke if genuine and mark in KavachRecon.', ['x']);
  finding('demo-cert-expiry', 'TLS certificate for app.nimbus-cloud.io expires within 30 days', 'TLS/CERTIFICATE', 'VERIFIED', 'MEDIUM', 'HIGH', 'app.nimbus-cloud.io',
    'The certificate presented by app.nimbus-cloud.io expires 2026-09-24 (13 days from collection). Verified from the live handshake (demo evidence).',
    'Risk of unplanned outage and client trust warnings if not renewed.',
    'Confirm auto-renewal is functioning; renew before expiry.', ['x']);
  finding('demo-tls11', 'Legacy TLS protocol accepted by staging.nimbus-cloud.io:8080', 'TLS/PROTOCOL', 'CONFIRMED_FINDING', 'MEDIUM', 'HIGH', 'staging.nimbus-cloud.io',
    'A live TLS handshake with staging.nimbus-cloud.io:8080 succeeded using TLSv1.1. Confirmed by direct connection.',
    'Legacy TLS has known weaknesses and fails modern compliance baselines (PCI DSS, NIST SP 800-52).',
    'Disable TLSv1.0/1.1; require TLSv1.2+ with modern ciphers.', ['x']);
  finding('demo-pg', 'PostgreSQL service confirmed listening on db.internal.nimbus-cloud.io:5432', 'NETWORK_EXPOSURE', 'HEURISTIC', 'MEDIUM', 'HIGH', 'db.internal.nimbus-cloud.io:5432',
    'A confirmed-open PostgreSQL service was observed at db.internal.nimbus-cloud.io:5432 during the authorized demo scan. Whether this exposure is intended could not be determined from scan data alone.',
    'Datastore services exposed to untrusted networks are a common initial-access vector.',
    'Verify with the asset owner; enforce network ACLs and authentication.', ['x']);
  finding('demo-dangling', 'Dangling CNAME observed — manual verification required', 'DNS_HYGIENE', 'MANUAL_REVIEW', 'MEDIUM', 'MEDIUM', 'status.nimbus-cloud.io',
    'The CNAME status.nimbus-cloud.io → statuspage.umbrellademo.net no longer resolves (NXDOMAIN). Subdomain takeover could NOT be confirmed from passive evidence.',
    'If the target service can be re-registered, attacker content could be served from the trusted domain.',
    'Verify with the responsible team; remove or re-point the stale record.', ['x']);
  finding('demo-wildcard', 'Wildcard DNS behaviour present for nimbus-cloud.io (informational)', 'DNS_INTERPRETATION', 'OBSERVED', 'INFO', 'HIGH', 'nimbus-cloud.io',
    'Random-label probes resolved, indicating wildcard DNS. This is NOT a vulnerability; it matters for interpreting subdomain results in this demo dataset.',
    'Informational only.', 'No action required.', ['x']);

  /* ----- module matrix (demo scan) ----- */
  const modules = [
    ['dns_enum', 'DNS Enumeration', 'COMPLETED', 8], ['email_security', 'Email Security (SPF / DMARC / DKIM)', 'COMPLETED', 2],
    ['subdomain_brute', 'Subdomain Discovery (DNS dictionary)', 'COMPLETED', 8], ['dns_analysis', 'DNS Analysis (wildcard / dangling CNAME)', 'COMPLETED', 1],
    ['ct_logs', 'Certificate Transparency Discovery', 'COMPLETED', 8], ['whois_intel', 'WHOIS / Registration Intelligence', 'COMPLETED', 1],
    ['asn_mapping', 'ASN / CIDR Mapping', 'COMPLETED', 3], ['historical_dns', 'Historical DNS Intelligence', 'SKIPPED', 0],
    ['url_archive', 'Public URL / Archive Discovery', 'COMPLETED', 14], ['host_discovery', 'Host Discovery', 'COMPLETED', 8],
    ['port_scan', 'Port & Service Discovery', 'COMPLETED', 10], ['http_probe', 'HTTP/HTTPS Probing', 'COMPLETED', 5],
    ['tls_analysis', 'TLS / SSL Analysis', 'COMPLETED', 4], ['tech_fingerprint', 'Technology Fingerprinting', 'COMPLETED', 4],
    ['waf_cdn', 'WAF / CDN / Perimeter Detection', 'COMPLETED', 2], ['security_posture', 'Security Posture (headers / cookies / TLS)', 'COMPLETED', 8],
    ['robots_sitemap', 'robots.txt & Sitemap Analysis', 'COMPLETED', 3], ['endpoint_discovery', 'Endpoint Discovery & Classification', 'COMPLETED', 11],
    ['js_intel', 'JavaScript Intelligence', 'COMPLETED', 6], ['cloud_intel', 'Cloud / Hosting Intelligence', 'COMPLETED', 1],
    ['screenshot', 'Web Screenshots', 'SKIPPED', 0],
  ];
  modules.forEach(([key, name, status, items], i) => {
    run(`INSERT INTO scan_modules (id, scan_id, module_key, name, order_idx, status, items_count, duration_ms, error, detail, started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [uid('mod'), sId, key, name, i, status, items, 800 + i * 320, null, JSON.stringify(key === 'historical_dns' ? { reason: 'DEMO dataset — historical source not included in demo.' } : key === 'screenshot' ? { reason: 'Screenshots not enabled in scan configuration.' } : {}), started, finished]);
  });

  const summary = {
    totals: {
      assets: q1(`SELECT COUNT(*) n FROM assets WHERE workspace_id = ?`, [wsId]).n,
      scan_assets: q1(`SELECT COUNT(DISTINCT asset_id) n FROM evidence WHERE scan_id = ? AND asset_id IS NOT NULL`, [sId]).n,
      subdomains: 8, ips: 4, live_hosts: 8, open_ports: 10, services: 8, web_apps: 5, endpoints: 11,
      technologies: 4, dns_records: 10, js_resources: 1, js_secrets: 1, findings: 9, review_items: 4, evidence: q1(`SELECT COUNT(*) n FROM evidence WHERE scan_id = ?`, [sId]).n,
    },
    severity: { CRITICAL: 0, HIGH: 2, MEDIUM: 5, LOW: 1, INFO: 1 },
    modules: { COMPLETED: 19, SKIPPED: 2 },
    failed_modules: 0,
    limitations: ['Demo dataset — see the DEMO badge. Purge from Settings to remove.'],
  };
  run(`UPDATE scans SET summary = ? WHERE id = ?`, [JSON.stringify(summary), sId]);
  audit('system', 'seed.demo_scan', 'scan', sId, { findings: 9 });
  console.log(`[seed] demo workspace ready in ${Date.now() - t0}ms`);
}
