// KavachRecon — active reconnaissance: host discovery, port scanning, HTTP probing, TLS analysis
import { tcpConnect, tcpProbeService, tlsInspect, httpProbe, parseTitle, tryResolve, makeResolver, sleep } from '../../lib/netutil.js';
import { uid, run, now, q, q1 } from '../../db.js';

const QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017];
const EXTENDED_PORTS = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 500, 514, 587, 623, 636, 873, 990, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 4443, 4505, 4506, 5000, 5432, 5555, 5601, 5900, 5984, 6379, 6443, 6660, 6667, 7001, 7002, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9092, 9200, 9300, 11211, 15672, 27017, 27018, 50070];

export const hostDiscovery = {
  key: 'host_discovery', name: 'Host Discovery', description: 'Determines which in-scope hosts are reachable using TCP connect probes (ICMP is not used; hosts that block all probed ports will not be reported live).',
  requiresActive: true, timeoutMs: 180_000,
  async run(ctx) {
    const resolver = makeResolver();
    const hosts = [];
    if (ctx.target.type === 'DOMAIN') {
      // all DOMAIN/SUBDOMAIN assets resolve to candidate IPs
      const names = q(`SELECT key FROM assets WHERE workspace_id = ? AND type IN ('DOMAIN','SUBDOMAIN')`, [ctx.store.workspaceId]);
      for (const n of names) {
        const r = await tryResolve(resolver, n.key, 'A');
        for (const ip of (r.ok ? r.values : [])) if (!ctx.netGuard(ip)) hosts.push({ host: n.key, ip });
      }
    } else if (ctx.target.type === 'IP') {
      hosts.push({ host: ctx.target.identifier, ip: ctx.target.identifier });
    } else if (ctx.target.type === 'CIDR') {
      // first addresses of the CIDR (bounded)
      const [base, bits] = ctx.target.identifier.split('/');
      if (base.includes(':')) return { status: 'SKIPPED', detail: { reason: 'IPv6 CIDR host discovery not enabled in this build.' } };
      const n = Math.min(2 ** (32 - parseInt(bits)), 254);
      const toLong = (ip) => ip.split('.').reduce((a, o) => (a << 8) + +o, 0) >>> 0;
      const toIp = (l) => [24, 16, 8, 0].map(s => (l >>> s) & 255).join('.');
      const startL = toLong(base);
      const probePorts = [80, 443, 22];
      let alive = 0;
      for (let i = 1; i <= n; i++) {
        if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
        const ip = toIp(startL + i);
        const probe = await Promise.race(probePorts.map(p => tcpConnect(ip, p, 1200)));
        if (probe.ok) { recordHost(ctx, ip, ip, [probe]); alive++; }
      }
      return { status: alive ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { scanned: n, alive, method: 'TCP connect probes on 80/443/22' } };
    }
    if (!hosts.length) return { status: 'COMPLETED_NO_RESULTS', detail: { reason: 'No in-scope hosts resolved by earlier modules.' } };
    const uniq = new Map(); hosts.forEach(h => { if (!uniq.has(h.ip)) uniq.set(h.ip, h); });
    let alive = 0;
    for (const h of uniq.values()) {
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
      const blocked = ctx.netGuard(h.ip);
      if (blocked) continue;
      const probes = await Promise.all([80, 443, 22].map(p => tcpConnect(h.ip, p, 2500)));
      const anyOpen = probes.find(p => p.ok);
      if (anyOpen) { recordHost(ctx, h.host, h.ip, probes); alive++; }
      else {
        const hostAsset = ctx.store.addAsset({ type: 'HOST', key: h.host, value: h.host, status: 'UNREACHABLE' });
        ctx.store.addEvidence({ module_key: 'host_discovery', asset_id: hostAsset, kind: 'HOST_UNREACHABLE', source: 'TCP connect probes', summary: `${h.host} (${h.ip}) did not respond on ports 80/443/22 — host state unknown (may filter all probes)`, content: { host: h.host, ip: h.ip, probes: probes.map(p => p.error || 'ok') } });
      }
    }
    return { status: alive ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { method: 'TCP connect probes on 80/443/22 (ICMP not available)', candidates: uniq.size, alive } };
  },
};

function recordHost(ctx, host, ip, probes) {
  const hostAsset = ctx.store.addAsset({ type: 'HOST', key: host, value: host });
  const ipAsset = ctx.store.addAsset({ type: 'IP', key: ip, value: ip });
  ctx.store.addEdge(hostAsset, ipAsset, 'RESOLVES_TO');
  const openProbe = probes.find(p => p.ok);
  ctx.store.addEvidence({
    module_key: 'host_discovery', asset_id: hostAsset, kind: 'HOST_ALIVE', source: 'TCP connect probes',
    summary: `${host} (${ip}) responded to a TCP connect probe — host considered live`,
    content: { host, ip, evidence_port: openProbe?.port || null, probe_errors: probes.map(p => p.error).filter(Boolean) },
  });
  return hostAsset;
}

const PORT_SERVICES = { 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain/dns', 67: 'dhcp', 69: 'tftp', 80: 'http', 81: 'http-alt', 110: 'pop3', 111: 'rpcbind', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns', 139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 389: 'ldap', 443: 'https', 445: 'smb', 465: 'smtps', 500: 'isakmp', 514: 'syslog', 587: 'submission', 623: 'ipmi', 636: 'ldaps', 873: 'rsync', 990: 'ftps', 993: 'imaps', 995: 'pop3s', 1080: 'socks', 1194: 'openvpn', 1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 2049: 'nfs', 2082: 'cpanel', 2083: 'cpanel-ssl', 2181: 'zookeeper', 2375: 'docker', 2376: 'docker-tls', 3000: 'http-dev', 3128: 'squid', 3268: 'gcldap', 3306: 'mysql', 3389: 'rdp', 4443: 'https-alt', 4505: 'salt', 4506: 'salt', 5000: 'http-alt', 5432: 'postgresql', 5555: 'adb', 5601: 'kibana', 5900: 'vnc', 5984: 'couchdb', 6379: 'redis', 6443: 'kubernetes', 6660: 'irc', 6667: 'irc', 7001: 'weblogic', 7002: 'weblogic-ssl', 8000: 'http-alt', 8008: 'http-alt', 8009: 'ajp', 8080: 'http-proxy', 8081: 'http-alt', 8443: 'https-alt', 8888: 'http-alt', 9000: 'http-alt', 9090: 'http-alt', 9092: 'kafka', 9200: 'elasticsearch', 9300: 'elasticsearch', 11211: 'memcached', 15672: 'rabbitmq-mgmt', 27017: 'mongodb', 27018: 'mongodb', 50070: 'hadoop' };

export const portScan = {
  key: 'port_scan', name: 'Port & Service Discovery', description: 'TCP connect scan of the top service ports on live in-scope hosts. Every open port is confirmed with a protocol-aware probe before being labelled OPEN.',
  requiresActive: true, timeoutMs: 600_000,
  async run(ctx) {
    const hosts = q(`SELECT DISTINCT h.key AS host, i.key AS ip FROM assets h
      JOIN asset_edges e ON e.src_id = h.id AND e.relation = 'RESOLVES_TO'
      JOIN assets i ON i.id = e.dst_id AND i.type = 'IP'
      WHERE h.workspace_id = ? AND h.type IN ('HOST','DOMAIN','SUBDOMAIN') AND h.status != 'UNREACHABLE'`, [ctx.store.workspaceId]);
    if (!hosts.length && ctx.target.type === 'IP') hosts.push({ host: ctx.target.identifier, ip: ctx.target.identifier });
    if (!hosts.length) return { status: 'COMPLETED_NO_RESULTS', detail: { reason: 'No live hosts available from host discovery. Port scanning was not performed.' } };
    const ports = ctx.cfg.top_ports === 'extended' ? EXTENDED_PORTS : QUICK_PORTS;
    const sem = new (await import('../../lib/netutil.js')).Semaphore(24);
    let openCount = 0, unverified = 0, closed = 0, filtered = 0;
    for (const h of hosts) {
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled', open: openCount } };
      if (ctx.netGuard(h.ip)) continue;
      const hostAsset = ctx.store.addAsset({ type: 'HOST', key: h.host, value: h.host });
      for (const port of ports) {
        await ctx.rate.acquire(h.ip);
        const res = await sem.run(() => tcpConnect(h.ip, port, ctx.cfg.port_timeout_ms));
        if (res.ok) {
          // confirm with protocol-aware probe
          const probe = await tcpProbeService(h.ip, port, 4000);
          let state, service = PORT_SERVICES[port] || `port-${port}`, banner = null, confidence = 'MEDIUM';
          if (probe.ok && probe.banner && probe.banner.trim().length) {
            state = 'OPEN'; banner = probe.banner.slice(0, 500); confidence = 'HIGH';
            if (port === 443 || port === 8443 || port === 4443) service = 'https';
            // extract version-ish info only from real banners
            const vm = banner.match(/(OpenSSH_[\w.\-]+|vsftpd [\w.\-]+|Postfix|Exim [\w.\-]+|nginx\/[\w.\-]+|Apache\/[\w.\-]+|Microsoft-IIS\/[\w.\-]+|Redis[\w.\- ]*v?=[\w.\-]+|PostgreSQL [\w.\-]+)/i);
            const bannerText = vm ? vm[1] : null;
            recordPort(ctx, hostAsset, h, port, state, service, banner, bannerText, confidence);
            openCount++;
          } else if (probe.ok && !probe.banner && (port === 443 || port === 8443 || port === 4443)) {
            state = 'OPEN'; confidence = 'HIGH'; service = 'https';
            recordPort(ctx, hostAsset, h, port, state, service, null, null, confidence);
            openCount++;
          } else if (probe.error === 'timeout awaiting response') {
            state = 'OPEN_UNVERIFIED'; confidence = 'LOW';
            recordPort(ctx, hostAsset, h, port, state, service, null, null, confidence, 'TCP connect accepted but no service banner/response received — service identity unconfirmed');
            unverified++;
          } else {
            state = 'OPEN_UNVERIFIED'; confidence = 'LOW';
            recordPort(ctx, hostAsset, h, port, state, service, null, null, confidence, `TCP connect accepted; probe closed connection (${probe.error || 'no data'}) — service identity unconfirmed`);
            unverified++;
          }
        } else if (res.state === 'CLOSED') { closed++; }
        else { filtered++; }
      }
    }
    return {
      status: (openCount + unverified) ? 'COMPLETED' : 'COMPLETED_NO_RESULTS',
      detail: { ports_scanned: ports.length * hosts.length, open: openCount, open_unverified: unverified, closed: closed, filtered, note: unverified ? 'OPEN_UNVERIFIED ports had a TCP accept but no confirming service response; they are NOT counted as confirmed services.' : null },
    };
  },
};

function recordPort(ctx, hostAsset, h, port, state, service, banner, version, confidence, note) {
  const evId = ctx.store.addEvidence({
    module_key: 'port_scan', asset_id: hostAsset, kind: 'PORT_RESULT', source: 'TCP connect + protocol-aware service probe',
    summary: `${h.host} (${h.ip}) :${port}/tcp ${state}${service ? ` service≈${service}` : ''}${note ? ` — ${note}` : ''}`,
    content: { host: h.host, ip: h.ip, port, protocol: 'tcp', state, service, banner: banner || null, version: version || null, note: note || null },
  });
  const key = `${h.ip}:${port}/tcp`;
  const assetId = ctx.store.addAsset({ type: 'PORT', key, value: `${h.ip}:${port}/tcp (${state})`, parent_id: hostAsset });
  const svcAsset = service && state === 'OPEN' ? ctx.store.addAsset({ type: 'SERVICE', key: `${key}:${service}`, value: `${service} @ ${h.ip}:${port}`, parent_id: assetId, confidence }) : null;
  run(`INSERT INTO host_ports (id, scan_id, asset_id, host, ip, port, protocol, state, service, banner, version, confidence, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [uid('prt'), ctx.scan.id, assetId, h.host, h.ip, port, 'tcp', state, service, banner, version, confidence, evId, now()]);
  ctx.store.addEdge(hostAsset, assetId, 'HAS_PORT');
  if (svcAsset) ctx.store.addEdge(assetId, svcAsset, 'RUNS_SERVICE');
}

export const httpProbeModule = {
  key: 'http_probe', name: 'HTTP/HTTPS Probing', description: 'Probes web services on discovered hosts, capturing status, redirect chains, headers, titles and response metadata for every reachable URL.',
  requiresActive: true, timeoutMs: 420_000,
  async run(ctx) {
    // candidates: live web ports + standard ports on every host
    const candidates = [];
    const portRows = q(`SELECT DISTINCT ip, host, port FROM host_ports WHERE scan_id = ? AND state IN ('OPEN','OPEN_UNVERIFIED') AND port IN (80,443,8080,8443,8000,8888,3000,5000,7001,9090,4443)`, [ctx.scan.id]);
    for (const r of portRows) {
      candidates.push({ url: `http${r.port === 443 || r.port === 8443 || r.port === 4443 ? 's' : ''}://${r.host}:${r.port}`, host: r.host, ip: r.ip, port: r.port });
    }
    const hostRows = q(`SELECT DISTINCT host, ip FROM host_ports WHERE scan_id = ? AND state IN ('OPEN','OPEN_UNVERIFIED')`, [ctx.scan.id]);
    for (const r of hostRows) {
      for (const p of [80, 443]) {
        if (!portRows.some(x => x.ip === r.ip && x.port === p)) candidates.push({ url: `http${p === 443 ? 's' : ''}://${r.host}`, host: r.host, ip: r.ip, port: p });
      }
    }
    // de-dup by url
    const seen = new Set(); const list = [];
    for (const c of candidates) { if (!seen.has(c.url) && !ctx.netGuard(c.host) && !ctx.netGuard(c.ip)) { seen.add(c.url); list.push(c); } }
    if (!list.length) return { status: 'COMPLETED_NO_RESULTS', detail: { reason: 'No live web-port candidates were available from earlier modules. HTTP probing was NOT performed.' } };
    let observed = 0, unreachable = 0;
    let budget = ctx.cfg.max_http_targets;
    for (const c of list) {
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
      if (budget-- <= 0) break;
      const scheme = c.url.startsWith('https') ? 'https' : 'http';
      let tlsInfo = null;
      if (scheme === 'https') {
        if (ctx.netGuard(c.host) || ctx.netGuard(c.ip)) continue;
        tlsInfo = await tlsInspect(c.ip || c.host, c.port, c.host, 6000);
      }
      await ctx.rate.acquire(c.host);
      const res = await httpProbe(c.url, { timeout: ctx.cfg.http_timeout_ms, rateLimiter: ctx.rate, host: c.host });
      if (!res.ok) {
        unreachable++;
        const evId = ctx.store.addEvidence({ module_key: 'http_probe', kind: 'HTTP_UNREACHABLE', source: 'HTTP client', summary: `${c.url} unreachable: ${res.error}`, content: { url: c.url, error: res.error } });
        run(`INSERT INTO web_observations (id, scan_id, url, ok, headers, redirect_chain, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?)`,
          [uid('web'), ctx.scan.id, c.url, 0, '{}', '[]', evId, now()]);
        continue;
      }
      observed++;
      const title = parseTitle(res.body || '');
      const serverHeader = norm(res.headers['server']);
      const evId = ctx.store.addEvidence({
        module_key: 'http_probe', kind: 'HTTP_OBSERVATION', source: `HTTP ${res.status}`,
        summary: `${c.url} → ${res.status} (${title || 'no title'})${res.chain.length ? ` after ${res.chain.length} redirect(s)` : ''}`,
        content: { url: c.url, final_url: res.finalUrl, status: res.status, redirect_chain: res.chain, response_headers: res.headers, title, server: serverHeader, tls: tlsInfo, body_excerpt: (res.body || '').slice(0, 60_000) },
      });
      const hostAssetId = ctx.store.addAsset({ type: 'HOST', key: c.host, value: c.host });
      const urlId = ctx.store.addAsset({ type: 'URL', key: res.finalUrl.toLowerCase(), value: res.finalUrl, parent_id: hostAssetId });
      ctx.store.addEdge(hostAssetId, urlId, 'SERVES_URL');
      if (tlsInfo?.ok) {
        const certAsset = ctx.store.addAsset({ type: 'CERT', key: `cert:${c.host}:${tlsInfo.cert?.fingerprint256 || ''}`, value: `TLS certificate for ${c.host}`, parent_id: hostAssetId });
        ctx.store.addEdge(urlId, certAsset, 'USES_CERT');
      }
      run(`INSERT INTO web_observations (id, scan_id, asset_id, url, final_url, status_code, ok, redirect_chain, title, server, content_type, response_ms, headers, tls, evidence_id, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [uid('web'), ctx.scan.id, urlId, c.url, res.finalUrl, res.status, 1, JSON.stringify(res.chain), title, serverHeader, norm(res.headers['content-type']), null, JSON.stringify(res.headers), tlsInfo ? JSON.stringify(tlsInfo) : null, evId, now()]);
    }
    return { status: observed ? 'COMPLETED' : 'FAILED', detail: observed ? { observed, unreachable } : { reason: `No HTTP/HTTPS service responded (${unreachable} probes failed: blocked egress or no listeners). Web intelligence modules downstream will operate on zero observations — this is a data limitation, NOT evidence that no web applications exist.`, unreachable } };
  },
};

const norm = (v) => Array.isArray(v) ? v.join(', ') : (v ?? null);

export const tlsAnalysis = {
  key: 'tls_analysis', name: 'TLS / SSL Analysis', description: 'Inspects TLS protocol support, cipher selection and certificate properties for HTTPS services observed in this scan.',
  requiresActive: true, timeoutMs: 240_000,
  when: (ctx) => q(`SELECT COUNT(*) n FROM web_observations WHERE scan_id = ? AND url LIKE 'https:%' AND ok = 1`, [ctx.scan.id]).n > 0,
  whenReason: 'No reachable HTTPS services were observed, so there was nothing to analyse.',
  async run(ctx) {
    const targets = q(`SELECT DISTINCT url FROM web_observations WHERE scan_id = ? AND url LIKE 'https:%' AND ok = 1`, [ctx.scan.id]);
    let inspected = 0;
    for (const t of targets.slice(0, 25)) {
      const u = new URL(t.url);
      if (ctx.netGuard(u.hostname) || ctx.netGuard(u.hostname.replace(/^www\./, ''))) continue;
      const port = u.port || 443;
      const info = await tlsInspect(u.hostname, +port, u.hostname, 7000);
      const hostAsset = ctx.store.addAsset({ type: 'HOST', key: u.hostname, value: u.hostname });
      ctx.store.addEvidence({
        module_key: 'tls_analysis', asset_id: hostAsset, kind: 'TLS_INSPECTION', source: `TLS handshake ${u.hostname}:${port}`,
        summary: info.ok ? `${t.url}: ${info.protocol}, cipher ${info.cipher}, cert CN=${info.cert?.subject?.CN || 'n/a'}${info.legacySupport?.tls10 || info.legacySupport?.tls11 ? ', legacy TLS accepted' : ''}` : `${t.url}: handshake failed (${info.error})`,
        content: info,
      });
      inspected++;
    }
    return { status: inspected ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { inspected } };
  },
};

export const activeModules = [hostDiscovery, portScan, httpProbeModule, tlsAnalysis];
