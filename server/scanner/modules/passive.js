// KavachRecon — passive intelligence: CT logs, WHOIS/RDAP, ASN mapping, historical DNS, URL archives
import { tryResolve, makeResolver, tcpConnect, httpProbe, sleep } from '../../lib/netutil.js';
import { uid, run, now, q } from '../../db.js';

/* ---------- Certificate Transparency (crt.sh, real HTTPS API) ---------- */
export const ctLogs = {
  key: 'ct_logs', name: 'Certificate Transparency Discovery', description: 'Queries public CT logs (crt.sh) for certificates naming the authorized domain.',
  timeoutMs: 60_000,
  async run(ctx) {
    if (ctx.target.type !== 'DOMAIN') return { status: 'NOT_APPLICABLE', detail: { reason: `Target type ${ctx.target.type}; CT discovery applies to DOMAIN targets.` } };
    const domain = ctx.target.identifier;
    const url = `https://crt.sh/?q=%.${domain}&output=json`;
    const res = await fetchWithErr(url, 45_000);
    if (!res.ok) {
      return { status: 'FAILED', detail: { reason: `CT log source unreachable: ${res.error}`, source: url, note: 'Failure means certificate-based subdomain discovery could NOT be performed. This must not be read as "no certificates exist".' } };
    }
    let data;
    try { data = JSON.parse(res.body); } catch { return { status: 'FAILED', detail: { reason: 'CT source returned unparseable JSON', source: url } }; }
    const domId = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
    const names = new Set();
    for (const row of data) {
      for (const nv of String(row.name_value || '').split('\n')) {
        const n = nv.toLowerCase().replace(/\.$/, '').trim();
        if (!n) continue;
        const blocked = ctx.netGuard(n);
        if (blocked) continue;
        names.add(n);
      }
    }
    let added = 0;
    for (const n of names) {
      if (n === domain) continue;
      const subId = ctx.store.addAsset({ type: 'SUBDOMAIN', key: n, value: n, parent_id: domId, confidence: 'MEDIUM' });
      ctx.store.addEdge(domId, subId, 'HAS_SUBDOMAIN');
      added++;
    }
    ctx.store.addEvidence({
      module_key: 'ct_logs', asset_id: domId, kind: 'CT_LOG_QUERY', source: 'crt.sh (public CT logs)',
      summary: `crt.sh returned ${Array.isArray(data) ? data.length : 0} certificate entries; ${added} unique in-scope names recorded`,
      content: { source: url, entries: Array.isArray(data) ? data.length : 0, unique_names: added, sample: Array.isArray(data) ? data.slice(0, 5).map(d => ({ issuer: d.issuer_name, not_before: d.not_before, names: d.name_value })) : [] },
    });
    return { status: added ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { entries: Array.isArray(data) ? data.length : 0, unique_names: added } };
  },
};

/* ---------- WHOIS (RFC 3912 over TCP/43 + RDAP) ---------- */
function whoisQuery(server, query, timeout = 10_000) {
  return new Promise((resolve) => {
    import('node:net').then(({ connect }) => {
      const s = connect({ host: server, port: 43, timeout });
      let buf = '';
      const done = (r) => { try { s.destroy(); } catch {}; resolve(r); };
      s.setTimeout(timeout, () => done({ ok: false, error: 'timeout' }));
      s.on('error', (e) => done({ ok: false, error: e.code || e.message }));
      s.on('connect', () => s.write(query + '\r\n'));
      s.on('data', (c) => { buf += c.toString('utf8'); });
      s.on('close', () => done({ ok: buf.length > 0, body: buf, error: buf ? undefined : 'no data returned' }));
    });
  });
}

export const whoisIntel = {
  key: 'whois_intel', name: 'WHOIS / Registration Intelligence', description: 'Collects registration data via RDAP (HTTPS) and classic WHOIS (TCP/43) for the authorized target.',
  timeoutMs: 45_000,
  async run(ctx) {
    if (ctx.target.type !== 'DOMAIN') return { status: 'NOT_APPLICABLE', detail: { reason: `Target type ${ctx.target.type}; WHOIS applies to DOMAIN targets.` } };
    const domain = ctx.target.identifier;
    const domId = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
    // 1) RDAP via IANA bootstrap (HTTPS)
    const rdap = await fetchWithErr(`https://rdap.org/domain/${encodeURIComponent(domain)}`, 15_000, { accept: 'application/rdap+json' });
    let rdapParsed = null;
    if (rdap.ok) {
      try {
        rdapParsed = JSON.parse(rdap.body);
        const events = Object.fromEntries((rdapParsed.events || []).map(e => [e.eventAction, e.eventDate]));
        const registrar = (rdapParsed.entities || []).find(e => (e.roles || []).includes('registrar'));
        const registrarName = registrar?.vcardArray?.[1]?.find(x => x[0] === 'fn')?.[3];
        const nameservers = (rdapParsed.nameservers || []).map(n => String(n.ldhName || '').toLowerCase()).filter(Boolean);
        const status = rdapParsed.status || [];
        const summaryBits = { registrar: registrarName, creation: events.registration, expiry: events.expiration, status, nameservers };
        ctx.store.addEvidence({
          module_key: 'whois_intel', asset_id: domId, kind: 'WHOIS_RDAP', source: 'RDAP (rdap.org)',
          summary: `RDAP registration data for ${domain}: registrar=${registrarName || 'n/a'}, created=${events.registration || 'n/a'}, expires=${events.expiration || 'n/a'}`,
          content: summaryBits,
        });
        // nameserver assets
        for (const ns of nameservers.slice(0, 12)) {
          const nsId = ctx.store.addAsset({ type: 'HOST', key: ns, value: ns });
          ctx.store.addEdge(domId, nsId, 'DNS_SERVER');
        }
      } catch (e) { /* fall through to classic whois */ }
    }
    // 2) classic WHOIS: IANA → registrar server
    let whoisText = null;
    const iana = await whoisQuery('whois.iana.org', domain);
    if (iana.ok) {
      const refer = (iana.body.match(/refer:\s*(\S+)/i) || [])[1];
      whoisText = iana.body;
      if (refer) {
        const reg = await whoisQuery(refer, domain);
        if (reg.ok) whoisText = reg.body;
      }
      ctx.store.addEvidence({
        module_key: 'whois_intel', asset_id: domId, kind: 'WHOIS_TEXT', source: 'WHOIS TCP/43',
        summary: `WHOIS response received for ${domain} (${whoisText.length} bytes)`,
        content: { excerpt: whoisText.slice(0, 4000) },
      });
    }
    if (!rdap.ok && !whoisText) {
      return {
        status: 'FAILED',
        detail: {
          reason: `Both RDAP (${rdap.error || rdap.status}) and WHOIS TCP/43 (iana: ${iana.error || 'no data'}) were unreachable — registration intelligence could not be collected.`,
          note: 'This is a data-collection failure, not a finding about the domain.',
        },
      };
    }
    return { status: 'COMPLETED', detail: { rdap_ok: rdap.ok, whois_ok: !!whoisText } };
  },
};

/* ---------- ASN / CIDR mapping (Team Cymru IP-to-ASN + RDAP) ---------- */
export const asnMapping = {
  key: 'asn_mapping', name: 'ASN / CIDR Mapping', description: 'Maps discovered IPs to their origin ASN and network using Team Cymru IP-to-ASN and RDAP.',
  timeoutMs: 90_000,
  async run(ctx) {
    const ips = q(`SELECT id, key FROM assets WHERE workspace_id = ? AND type = 'IP' ORDER BY first_seen LIMIT 40`, [ctx.store.workspaceId]);
    if (!ips.length) return { status: 'COMPLETED_NO_RESULTS', detail: { reason: 'No IP assets discovered by earlier modules; nothing to map.' } };
    let mapped = 0, failed = 0;
    for (const ip of ips) {
      if (ctx.cancelled()) return { status: 'SKIPPED', detail: { reason: 'cancelled' } };
      // Team Cymru over whois (TCP/43)
      const w = await whoisQuery('whois.arin.net', ` -v ${ip.key}`); // ARIN whois -v gives origin ASN
      const cymru = await whoisQuery('asn.team-cymru.com', `${ip.key} AS(N) ORIGIN`);
      let asn = null, asnName = null, cidr = null, country = null, method = null;
      if (cymru.ok && /AS\d+/.test(cymru.body)) {
        const m = cymru.body.match(/AS(\d+)\s*\|\s*([A-Z]{2})\s*\|\s*([^\|]*)\|\s*([0-9.\/]+)/);
        if (m) { asn = `AS${m[1]}`; country = m[2].trim(); asnName = m[3].trim(); cidr = m[4].trim(); method = 'Team Cymru IP-to-ASN (WHOIS TCP/43)'; }
        else {
          const lines = cymru.body.split('\n').filter(l => /AS\d+/.test(l));
          if (lines.length) { const parts = lines[0].split('|'); asn = `AS${(parts[0].match(/\d+/) || [''])[0]}`; country = (parts[1] || '').trim(); asnName = (parts[2] || '').trim(); cidr = (parts[3] || '').trim(); method = 'Team Cymru IP-to-ASN (WHOIS TCP/43)'; }
        }
      }
      if (!asn && w.ok) {
        const origin = (w.body.match(/OriginAS:\s*(\S+)/i) || w.body.match(/origin:\s*(\S+)/im) || [])[1];
        const netName = (w.body.match(/NetName:\s*(.+)/i) || [])[1];
        const cidrM = (w.body.match(/CIDR:\s*(.+)/i) || [])[1];
        if (origin || netName) { asn = origin || null; asnName = netName?.trim() || null; cidr = cidrM?.trim() || null; method = 'ARIN WHOIS (TCP/43)'; }
      }
      if (asn) {
        mapped++;
        ctx.store.addEvidence({
          module_key: 'asn_mapping', asset_id: ip.id, kind: 'ASN_MAPPING', source: method,
          summary: `${ip.key} → ${asn} ${asnName || ''} ${cidr || ''} (${country || '??'})`,
          content: { ip: ip.key, asn, asn_name: asnName, cidr, country, method },
        });
        if (cidr) {
          const cidrKey = cidr.split(',')[0].trim();
          if (ctx.netGuard(cidrKey) === null) {
            const cId = ctx.store.addAsset({ type: 'CIDR', key: cidrKey.toLowerCase(), value: cidrKey, confidence: 'HIGH' });
            ctx.store.addEdge(cId, ip.id, 'CONTAINS');
          }
        }
      } else {
        failed++;
      }
      await sleep(150); // be polite to whois infra
    }
    if (mapped === 0 && failed > 0) {
      return { status: 'FAILED', detail: { reason: `None of ${failed} IP assets could be mapped to an ASN — ASN data sources were unreachable. No ASN/CIDR conclusions can be drawn from this scan.`, ips_checked: failed } };
    }
    return { status: mapped ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { mapped, unmapped: failed } };
  },
};

/* ---------- Historical DNS (FreeAPI: hackertarget? uses HTTPS sources) ---------- */
export const historicalDns = {
  key: 'historical_dns', name: 'Historical DNS Intelligence', description: 'Retrieves historical DNS observations from public archives where reachable.',
  timeoutMs: 45_000,
  async run(ctx) {
    if (ctx.target.type !== 'DOMAIN') return { status: 'NOT_APPLICABLE', detail: { reason: `Target type ${ctx.target.type}.` } };
    const domain = ctx.target.identifier;
    // SecurityTrails/PassiveTotal need keys; use the open hackertarget host-search API (free, rate-limited)
    const res = await fetchWithErr(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, 20_000);
    if (!res.ok) {
      return { status: 'FAILED', detail: { reason: `Historical DNS source unreachable: ${res.error}. No historical records were collected.`, source: 'api.hackertarget.com' } };
    }
    const body = res.body || '';
    if (body.includes('API count exceeded')) {
      return { status: 'SKIPPED', detail: { reason: 'Public API rate limit reached (free tier). Historical DNS data unavailable for this scan — not an indication of "no history".' } };
    }
    let added = 0;
    const domId = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
    for (const line of body.split('\n').slice(0, 200)) {
      const [host, ip] = line.split(',');
      if (!host || !ip) continue;
      if (ctx.netGuard(host)) continue;
      const subId = ctx.store.addAsset({ type: 'SUBDOMAIN', key: host.toLowerCase(), value: host.toLowerCase(), parent_id: domId });
      ctx.store.addEdge(domId, subId, 'HAS_SUBDOMAIN');
      const ipId = ctx.store.addAsset({ type: 'IP', key: ip.toLowerCase(), value: ip });
      ctx.store.addEdge(subId, ipId, 'RESOLVED_HISTORICALLY');
      added++;
    }
    ctx.store.addEvidence({ module_key: 'historical_dns', asset_id: domId, kind: 'HISTORICAL_DNS', source: 'api.hackertarget.com hostsearch', summary: `${added} host→ip historical pairs recorded for ${domain}`, content: { added } });
    return { status: added ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { added } };
  },
};

/* ---------- Public URL / archive discovery (Wayback CDX) ---------- */
export const urlArchive = {
  key: 'url_archive', name: 'Public URL / Archive Discovery', description: 'Discovers historically observed URLs for the target via the Internet Archive CDX API.',
  timeoutMs: 60_000,
  async run(ctx) {
    if (ctx.target.type !== 'DOMAIN') return { status: 'NOT_APPLICABLE', detail: { reason: `Target type ${ctx.target.type}.` } };
    const domain = ctx.target.identifier;
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&collapse=urlkey&limit=300&fl=original,statuscode,mimetype,timestamp`;
    const res = await fetchWithErr(url, 45_000);
    if (!res.ok) {
      return { status: 'FAILED', detail: { reason: `Internet Archive CDX unreachable: ${res.error}. Historical URL discovery was NOT performed — this is not evidence that no URLs exist.`, source: url } };
    }
    let rows;
    try { rows = JSON.parse(res.body); } catch { return { status: 'FAILED', detail: { reason: 'CDX returned unparseable data.' } }; }
    const domId = ctx.store.addAsset({ type: 'DOMAIN', key: domain, value: domain });
    let added = 0;
    for (const row of (rows || []).slice(1)) {
      const [original, statuscode, mimetype, timestamp] = row;
      if (!original || ctx.netGuard(original)) continue;
      const uId = ctx.store.addAsset({ type: 'URL', key: original.toLowerCase(), value: original, meta: {} });
      ctx.store.addEdge(domId, uId, 'ARCHIVED_URL');
      ctx.store.addEvidence({
        module_key: 'url_archive', asset_id: uId, kind: 'ARCHIVED_URL', source: 'Internet Archive CDX',
        summary: `Archived URL ${original} (status ${statuscode}, snapshot ${timestamp})`,
        content: { original, statuscode, mimetype, timestamp },
      });
      added++;
    }
    return { status: added ? 'COMPLETED' : 'COMPLETED_NO_RESULTS', detail: { archived_urls: added } };
  },
};

/* ---------- shared helper ---------- */
export async function fetchWithErr(url, timeout = 15_000, headers = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(new Error('timeout')), timeout);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'KavachRecon/1.0 (+authorized-recon)', ...headers } });
    const body = await res.text();
    return { ok: res.ok, status: res.status, body, error: res.ok ? undefined : `HTTP ${res.status}` };
  } catch (e) {
    return { ok: false, status: null, body: '', error: e?.cause?.code || e.message || 'network error' };
  } finally { clearTimeout(t); }
}

export const passiveModules = [ctLogs, whoisIntel, asnMapping, historicalDns, urlArchive];
