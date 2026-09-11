// KavachRecon — DNS intelligence modules (real DNS queries via UDP/53)
import { makeResolver, tryResolve, RR_TYPES, reverseZone } from '../../lib/netutil.js';
import { uid, run, now, q } from '../../db.js';

const SUBDOMAIN_WORDLIST = [
  'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'm', 'shop', 'ftp', 'mail2',
  'test', 'portal', 'ns', 'ww1', 'host', 'support', 'dev', 'web', 'bbs', 'mx', 'email', 'cloud', '1', 'mail1', 'relay',
  'api', 'app', 'admin', 'staging', 'beta', 'demo', 'git', 'jenkins', 'ci', 'cdn', 'assets', 'static', 'img', 'media',
  'intranet', 'corp', 'vpn2', 'gateway', 'gw', 'proxy', 'auth', 'sso', 'login', 'account', 'dashboard', 'status',
  'monitor', 'grafana', 'kibana', 'elastic', 'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongo', 's3',
  'storage', 'backup', 'old', 'new', 'sandbox', 'uat', 'preprod', 'prod', 'internal', 'private', 'office', 'exchange',
  'autodiscover', 'cpanel', 'whm', 'webdisk', 'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'gh', 'gitlab', 'jira', 'confluence',
  'wiki', 'docs', 'help', 'docs2', 'career', 'jobs', 'partner', 'partners', 'client', 'clients', 'crm', 'erp', 'hr',
];

export const dnsEnum = {
  key: 'dns_enum', name: 'DNS Enumeration', description: 'Queries A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR records for the authorized target.',
  timeoutMs: 90_000,
  async run(ctx) {
    const resolver = makeResolver();
    const domain = ctx.target.identifier;
    const records = [];
    for (const type of RR_TYPES) {
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
      const targetName = type === 'PTR' ? null : domain;
      if (type === 'PTR') continue; // PTR handled per-IP below
      const r = await tryResolve(resolver, domain, type);
      if (r.ok && r.values?.length) {
        for (const value of r.values) {
          const assetId = recordAssetForRR(ctx, type, domain, value);
          const evId = ctx.store.addEvidence({
            module_key: 'dns_enum', asset_id: assetId, kind: 'DNS_RECORD', source: `DNS resolver (${resolver.getServers().join(',')})`,
            summary: `${domain} ${type} → ${String(value).slice(0, 200)}`,
            content: { domain, type, name: domain, value, query: `${type} ${domain}` },
          });
          insertDns(ctx, { domain, type, name: domain, value, evId, assetId, meta: {} });
          records.push({ type, value });
        }
      } else if (!r.ok && !r.nxdomain && !['ENODATA'].includes(r.code)) {
        ctx.log(`DNS ${type} ${domain}: ${r.code || r.error}`);
      }
    }
    // reverse DNS for discovered IPs in this scan
    const ips = ctx.store.moduleItems.get('_ips') ? [] : [];
    const ipAssets = await import('../../db.js').then(({ q }) => q(
      `SELECT id, key FROM assets WHERE workspace_id = ? AND type = 'IP'`, [ctx.store.workspaceId]));
    for (const ip of ipAssets.slice(0, 60)) {
      const ptrName = reverseZone(ip.key);
      const r = await tryResolve(resolver, ptrName, 'PTR');
      if (r.ok && r.values?.length) {
        const hostAsset = ctx.store.addAsset({ type: 'HOST', key: r.values[0], value: r.values[0] });
        const evId = ctx.store.addEvidence({
          module_key: 'dns_enum', asset_id: hostAsset, kind: 'DNS_RECORD', source: 'DNS resolver (PTR)',
          summary: `${ip.key} PTR → ${r.values[0]}`, content: { domain: ip.key, type: 'PTR', name: ptrName, value: r.values[0] },
        });
        insertDns(ctx, { domain: ip.key, type: 'PTR', name: ptrName, value: r.values[0], evId, assetId: hostAsset, meta: {} });
        records.push({ type: 'PTR', value: r.values[0] });
        ctx.store.addEdge(ip.id, hostAsset, 'PTR_TO');
      }
    }
    return { status: records.length ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { resolver: resolver.getServers(), counts: Object.fromEntries(RR_TYPES.map(t => [t, records.filter(r => r.type === t).length])) } };
  },
};

function recordAssetForRR(ctx, type, domain, value) {
  if (type === 'A' || type === 'AAAA') {
    const ipId = ctx.store.addAsset({ type: 'IP', key: String(value), value: String(value) });
    const domId = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
    ctx.store.addEdge(domId, ipId, 'RESOLVES_TO');
    return ipId;
  }
  if (type === 'CNAME') {
    const target = String(value).toLowerCase();
    const tId = ctx.store.addAsset({ type: 'HOST', key: target, value: target });
    return tId;
  }
  if (type === 'MX') {
    const parts = String(value).trim().split(/\s+/);
    let host = parts.length > 1 ? parts.slice(1).join(' ') : String(value);
    host = host.trim().replace(/\.$/, '') || String(value).trim();
    if (!host || host === '.') return null;
    const hId = ctx.store.addAsset({ type: 'HOST', key: host.toLowerCase(), value: host });
    return hId;
  }
  if (type === 'NS') {
    const hId = ctx.store.addAsset({ type: 'HOST', key: String(value).toLowerCase().replace(/\.$/, ''), value: String(value) });
    return hId;
  }
  return ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
}

function insertDns(ctx, { domain, type, name, value, evId, assetId, meta }) {
  run(`INSERT INTO dns_records (id, scan_id, asset_id, domain, type, name, value, ttl, meta, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
    [uid('dns'), ctx.scan.id, assetId, domain, type, name, String(value), meta.ttl ?? null, JSON.stringify(meta), now()]);
  if (evId && assetId) run(`UPDATE evidence SET asset_id = COALESCE(asset_id, ?) WHERE id = ?`, [assetId, evId]);
}

export const emailSecurity = {
  key: 'email_security', name: 'Email Security (SPF / DMARC / DKIM)', description: 'Discovers SPF, DMARC and DKIM policy records where they exist.',
  timeoutMs: 60_000,
  async run(ctx) {
    const resolver = makeResolver();
    const domain = ctx.target.identifier;
    let found = 0;
    const checks = [
      { name: domain, label: 'SPF', selector: null },
      { name: `_dmarc.${domain}`, label: 'DMARC', selector: null },
      { name: domain, label: 'DKIM (default)', selector: 'default._domainkey' },
      { name: domain, label: 'DKIM (selector: google)', selector: 'google._domainkey' },
      { name: domain, label: 'DKIM (selector: selector1)', selector: 'selector1._domainkey' },
      { name: domain, label: 'DKIM (selector: selector2)', selector: 'selector2._domainkey' },
      { name: domain, label: 'DKIM (selector: k1)', selector: 'k1._domainkey' },
      { name: domain, label: 'DKIM (selector: s1)', selector: 's1._domainkey' },
      { name: domain, label: 'DKIM (selector: dkim)', selector: 'dkim._domainkey' },
      { name: domain, label: 'DKIM (selector: mail)', selector: 'mail._domainkey' },
    ];
    for (const c of checks) {
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
      const full = c.selector ? `${c.selector}.${domain}` : c.name;
      const r = await tryResolve(resolver, full, 'TXT');
      // record absence evidence for SPF/DMARC so findings can link to the actual query
      if (!r.ok && !c.selector && (c.label === 'SPF' || c.label === 'DMARC')) {
        const domId0 = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
        ctx.store.addEvidence({
          module_key: 'email_security', asset_id: domId0, kind: 'DNS_ABSENCE', source: 'DNS resolver (TXT query)',
          summary: `${full} TXT → no ${c.label} record returned (${r.code || 'no data'})`,
          content: { domain, type: 'TXT', name: full, label: c.label, result_code: r.code || 'ENODATA', absence: true },
        });
      }
      const vals = (r.ok ? r.values : []).filter(v => c.label.startsWith('SPF') ? v.toLowerCase().startsWith('v=spf1') : c.label.startsWith('DMARC') ? v.toLowerCase().startsWith('v=dmarc1') : true);
      if (vals.length) {
        for (const v of vals.slice(0, 3)) {
          const domId = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
          const evId = ctx.store.addEvidence({
            module_key: 'email_security', asset_id: domId, kind: 'DNS_RECORD', source: 'DNS resolver (TXT)',
            summary: `${full} TXT → ${v.slice(0, 180)}`, content: { domain, type: 'TXT', name: full, value: v, label: c.label },
          });
          insertDns(ctx, { domain, type: 'TXT', name: full, value: v, evId, assetId: domId, meta: { label: c.label } });
          found++;
        }
      }
    }
    return { status: found ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { note: found ? null : 'No SPF/DMARC/DKIM records were returned by the queried selectors. Absence of a record is an observation, not a confirmed vulnerability.' } };
  },
};

export const subdomainBrute = {
  key: 'subdomain_brute', name: 'Subdomain Discovery (DNS dictionary)', description: 'Resolves a curated dictionary of common subdomain labels against the authorized domain.',
  timeoutMs: 180_000,
  async run(ctx) {
    if (ctx.target.type !== 'DOMAIN') {
      return { status: 'NOT_APPLICABLE', detail: { reason: `Target is of type ${ctx.target.type}; dictionary subdomain discovery applies to DOMAIN targets.` } };
    }
    const resolver = makeResolver();
    const domain = ctx.target.identifier;
    const domId = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
    let discovered = 0;
    const batchSize = 10;
    for (let i = 0; i < SUBDOMAIN_WORDLIST.length; i += batchSize) {
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
      const batch = SUBDOMAIN_WORDLIST.slice(i, i + batchSize);
      const results = await Promise.all(batch.map(async (label) => {
        const host = `${label}.${domain}`;
        const blocked = ctx.netGuard(host);
        if (blocked) return null;
        const a = await tryResolve(resolver, host, 'A');
        const cname = await tryResolve(resolver, host, 'CNAME');
        if (a.ok || cname.ok) {
          return { host, label, a: a.ok ? a.values : [], cname: cname.ok ? cname.values : [] };
        }
        return null;
      }));
      for (const r of results.filter(Boolean)) {
        const subId = ctx.store.addAsset({ type: 'SUBDOMAIN', key: r.host, value: r.host, parent_id: domId, confidence: 'HIGH' });
        ctx.store.addEdge(domId, subId, 'HAS_SUBDOMAIN');
        ctx.store.addEvidence({
          module_key: 'subdomain_brute', asset_id: subId, kind: 'DNS_RESOLVE', source: 'DNS resolver (dictionary probe)',
          summary: `${r.host} resolves: A=[${r.a.join(', ')}]${r.cname.length ? ` CNAME=[${r.cname.join(', ')}]` : ''}`,
          content: { host: r.host, A: r.a, CNAME: r.cname },
        });
        for (const ip of r.a) {
          const ipId = ctx.store.addAsset({ type: 'IP', key: ip.toLowerCase(), value: ip });
          ctx.store.addEdge(subId, ipId, 'RESOLVES_TO');
        }
        for (const cn of r.cname) {
          const cId = ctx.store.addAsset({ type: 'HOST', key: cn.toLowerCase().replace(/\.$/, ''), value: cn });
          ctx.store.addEdge(subId, cId, 'CNAME_TO');
        }
        discovered++;
      }
    }
    return { status: discovered ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { dictionary_size: SUBDOMAIN_WORDLIST.length, discovered } };
  },
};

// wildcard detection & dangling CNAME analysis
export const dnsAnalysis = {
  key: 'dns_analysis', name: 'DNS Analysis (wildcard / dangling CNAME)', description: 'Detects wildcard DNS behaviour and CNAME records whose target does not resolve. Reports observations only — findings require evidence-based rules.',
  timeoutMs: 90_000,
  async run(ctx) {
    if (ctx.target.type !== 'DOMAIN') return { status: 'NOT_APPLICABLE', detail: { reason: 'Applies to DOMAIN targets.' } };
    const resolver = makeResolver();
    const domain = ctx.target.identifier;
    // wildcard test: two random labels
    const rnd = () => 'kr' + Math.random().toString(36).slice(2, 12);
    const w1 = await tryResolve(resolver, `${rnd()}.${domain}`, 'A');
    const w2 = await tryResolve(resolver, `${rnd()}.${domain}`, 'A');
    const wildcard = w1.ok && w2.ok;
    const domId = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
    ctx.store.addEvidence({
      module_key: 'dns_analysis', asset_id: domId, kind: 'DNS_WILDCARD_TEST', source: 'DNS resolver',
      summary: wildcard ? `Random labels resolve — wildcard DNS behaviour present (${w1.values.join(', ')} / ${w2.values.join(', ')})` : 'Random labels did not resolve — no wildcard DNS behaviour detected in A queries',
      content: { probe1: { name: `${rnd()}.${domain}`, ...w1 }, probe2: { ...w2 } },
    });
    // dangling CNAMEs across this scan's HOST assets reached via CNAME edges
    const { q } = await import('../../db.js');
    const cnames = q(`SELECT e.src_id, e.dst_id, a2.key AS target FROM asset_edges e JOIN assets a2 ON a2.id = e.dst_id WHERE e.workspace_id = ? AND e.relation = 'CNAME_TO'`, [ctx.store.workspaceId]);
    let dangling = 0;
    for (const cn of cnames) {
      const r = await tryResolve(resolver, cn.target, 'A');
      const a6 = await tryResolve(resolver, cn.target, 'AAAA');
      if (!r.ok && !a6.ok && (r.nxdomain || a6.nxdomain || r.code === 'ENOTFOUND')) {
        dangling++;
        ctx.store.addEvidence({
          module_key: 'dns_analysis', asset_id: cn.src_id, kind: 'DNS_DANGLING_CNAME', source: 'DNS resolver',
          summary: `CNAME target ${cn.target} did not resolve (A/AAAA ${r.code || a6.code || 'NXDOMAIN'}) — potential dangling record`,
          content: { cname_target: cn.target, result: { A: r, AAAA: a6 } },
        });
      }
    }
    return {
      status: 'COMPLETED',
      detail: { wildcard_present: wildcard, wildcard_note: wildcard ? 'Because wildcard DNS is present, non-existent subdomains may still resolve — subdomain findings in this scan should be treated with that in mind.' : null, dangling_cnames: dangling },
    };
  },
};

export const dnsModules = [dnsEnum, emailSecurity, subdomainBrute, dnsAnalysis];
