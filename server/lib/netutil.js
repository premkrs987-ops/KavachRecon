// KavachRecon — scope enforcement & network helpers (real implementations)
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import { Resolver } from 'node:dns/promises';

/* ---------------- Scope ---------------- */

export function ipToLong(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
}
export function inCidr(ip, cidr) {
  const [base, bitsRaw] = cidr.split('/');
  const bits = parseInt(bitsRaw, 10);
  if (net.isIPv4(ip) && net.isIPv4(base)) {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ipToLong(ip) & mask) === (ipToLong(base) & mask);
  }
  // IPv6 prefix compare
  try {
    const norm = (a) => { const [head] = a.split('/'); return expandV6(head); };
    const p = Math.min(bits, 128);
    const a = norm(ip).slice(0, Math.ceil(p / 8) * 2);
    const b = norm(base).slice(0, Math.ceil(p / 8) * 2);
    return a.startsWith(b.slice(0, Math.ceil(p / 8) * 2)) ;
  } catch { return false; }
}
function expandV6(addr) {
  const [h, t] = addr.split('::');
  const hl = h ? h.split(':') : [];
  const tl = t ? t.split(':') : [];
  const missing = 8 - hl.length - tl.length;
  const groups = [...hl, ...Array(missing).fill('0'), ...tl];
  return groups.map((g) => g.padStart(4, '0')).join('');
}
export function domainMatches(host, domain) {
  const h = host.toLowerCase().replace(/\.$/, '');
  const d = domain.toLowerCase().replace(/\.$/, '');
  return h === d || h.endsWith('.' + d);
}
export function wildcardMatches(host, pattern) {
  // pattern like *.api.example.com
  const rx = new RegExp('^' + pattern.split('.').map(p => p === '*' ? '[^.]+' : p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('\\.') + '$', 'i');
  return rx.test(host);
}

export class Scope {
  constructor(target, includeRules = [], excludeRules = []) {
    this.target = target; // {identifier,type}
    this.includes = includeRules;   // [{pattern,pattern_type}]
    this.excludes = excludeRules;   // [{pattern,pattern_type,reason}]
  }
  /** Returns {allowed:bool, reason} — every network operation must pass here. */
  check(hostOrIp) {
    let v = String(hostOrIp || '').toLowerCase().trim().replace(/^\w+:\/\//, '').split('/')[0].split(':')[0].replace(/\.$/, '');
    if (!v) return { allowed: false, reason: 'empty value' };
    // explicit excludes always win
    for (const r of this.excludes) {
      if (r.pattern_type === 'IP' && r.pattern === v) return { allowed: false, reason: `excluded IP ${r.pattern}` };
      if (r.pattern_type === 'CIDR' && net.isIPv4(v) && inCidr(v, r.pattern)) return { allowed: false, reason: `excluded CIDR ${r.pattern}` };
      if (r.pattern_type === 'DOMAIN' && domainMatches(v, r.pattern)) return { allowed: false, reason: `excluded domain ${r.pattern}` };
      if (r.pattern_type === 'WILDCARD' && wildcardMatches(v, r.pattern)) return { allowed: false, reason: `excluded wildcard ${r.pattern}` };
    }
    // the target itself
    if (this.target.type === 'DOMAIN' && domainMatches(v, this.target.identifier)) return { allowed: true, reason: 'within authorized domain' };
    if (this.target.type === 'IP' && v === this.target.identifier) return { allowed: true, reason: 'authorized IP' };
    if (this.target.type === 'CIDR' && (net.isIPv4(v) || v.includes(':')) && inCidr(v, this.target.identifier)) return { allowed: true, reason: 'within authorized CIDR' };
    // includes
    for (const r of this.includes) {
      if (r.pattern_type === 'DOMAIN' && domainMatches(v, r.pattern)) return { allowed: true, reason: `included domain ${r.pattern}` };
      if (r.pattern_type === 'IP' && r.pattern === v) return { allowed: true, reason: `included IP ${r.pattern}` };
      if (r.pattern_type === 'CIDR' && net.isIPv4(v) && inCidr(v, r.pattern)) return { allowed: true, reason: `included CIDR ${r.pattern}` };
      if (r.pattern_type === 'WILDCARD' && wildcardMatches(v, r.pattern)) return { allowed: true, reason: `included wildcard ${r.pattern}` };
    }
    return { allowed: false, reason: 'outside authorized scope' };
  }
}

/* ---------------- DNS ---------------- */

const RESOLVERS = process.env.KR_DNS_RESOLVERS ? process.env.KR_DNS_RESOLVERS.split(',') : ['8.8.8.8', '1.1.1.1'];

export function makeResolver(timeout = 5000, attempts = 2) {
  const r = new Resolver({ timeout, tries: attempts });
  r.setServers(RESOLVERS);
  return r;
}

export const RR_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'PTR'];

export async function resolveRR(resolver, name, type) {
  const map = {
    A: 'resolve4', AAAA: 'resolve6', CNAME: 'resolveCname', MX: 'resolveMx', NS: 'resolveNs',
    TXT: 'resolveTxt', SOA: 'resolveSoa', CAA: 'resolveCaa', PTR: 'resolvePtr', SRV: 'resolveSrv',
    NAPTR: 'resolveNaptr', SPF: 'resolveTxt',
  };
  const fn = map[type];
  if (!fn) throw new Error(`unsupported type ${type}`);
  const res = await resolver[fn](name);
  if (type === 'MX') return res.map(r => `${r.priority} ${r.exchange}`);
  if (type === 'TXT' || type === 'SPF') return res.map(chunks => chunks.join(''));
  if (type === 'CAA') return res.map(r => JSON.stringify(r));
  if (type === 'SOA') return [JSON.stringify(res)];
  return Array.isArray(res) ? res.map(String) : [String(res)];
}

export async function tryResolve(resolver, name, type) {
  try { return { ok: true, values: await resolveRR(resolver, name, type) }; }
  catch (e) {
    const code = e.code || e.errno || 'ERROR';
    const nrc = ['ENOTFOUND', 'ENODATA', 'NOTFOUND'].includes(code);
    return { ok: false, nxdomain: nrc, code, error: e.message };
  }
}

export function reverseZone(ip) {
  if (net.isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  const full = expandV6(ip).match(/.{4}/g).join('');
  return full.split('').reverse().join('.') + '.ip6.arpa';
}

/* ---------------- Rate limiting ---------------- */

export class RateLimiter {
  constructor({ globalRps = 30, perHostRps = 6 } = {}) {
    this.globalRps = globalRps; this.perHostRps = perHostRps;
    this.hostBuckets = new Map();
    this.globalTokens = globalRps; this.globalLast = Date.now();
  }
  #refill(tokens, last, rps) {
    const nowT = Date.now();
    const t = Math.min(rps, tokens + ((nowT - last) / 1000) * rps);
    return { tokens: t, last: nowT };
  }
  async acquire(host = '_global') {
    // global bucket
    let g = this.#refill(this.globalTokens, this.globalLast, this.globalRps);
    while (g.tokens < 1) { await sleep(50); g = this.#refill(g.tokens, g.last, this.globalRps); }
    this.globalTokens = g.tokens - 1; this.globalLast = g.last;
    // host bucket
    let b = this.hostBuckets.get(host) || { tokens: this.perHostRps, last: Date.now() };
    b = this.#refill(b.tokens, b.last, this.perHostRps);
    while (b.tokens < 1) { await sleep(50); b = this.#refill(b.tokens, b.last, this.perHostRps); }
    this.hostBuckets.set(host, { tokens: b.tokens - 1, last: b.last });
  }
}

export class Semaphore {
  constructor(n) { this.n = n; this.queue = []; }
  async run(fn) {
    if (this.n <= 0) await new Promise(res => this.queue.push(res));
    else this.n--;
    try { return await fn(); } finally {
      this.n++;
      const next = this.queue.shift();
      if (next) next();
    }
  }
}

export const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/* ---------------- TCP / HTTP probes (real) ---------------- */

export function tcpConnect(host, port, timeout = 4000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const s = net.connect({ host, port, timeout });
    let settled = false;
    const done = (result) => { if (!settled) { settled = true; try { s.destroy(); } catch {} resolve(result); } };
    s.on('connect', () => done({ ok: true, ms: Date.now() - start, socket: null }));
    s.on('timeout', () => done({ ok: false, state: 'FILTERED', error: 'timeout' }));
    s.on('error', (e) => done({ ok: false, state: e.code === 'ECONNREFUSED' ? 'CLOSED' : (['EHOSTUNREACH', 'ENETUNREACH'].includes(e.code) ? 'FILTERED' : 'UNKNOWN'), error: e.code || e.message }));
    s.on('close', () => done({ ok: false, state: 'UNKNOWN', error: 'closed before connect' }));
  });
}

const SERVICE_PROBES = {
  21: 'banner', 22: 'banner', 25: 'banner', 110: 'banner', 143: 'banner', 587: 'banner', 993: 'banner', 995: 'banner',
  3306: 'banner', 5432: 'banner', 6379: 'banner', 11211: 'banner', 27017: 'banner', 9200: 'banner',
  80: 'http', 8080: 'http', 8000: 'http', 8888: 'http', 3000: 'http', 5000: 'http', 7001: 'http', 9090: 'http',
  443: 'tls', 8443: 'tls', 4443: 'tls',
};

export function tcpProbeService(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, timeout });
    let buf = ''; let settled = false;
    const mode = SERVICE_PROBES[port] || 'banner';
    const done = (r) => { if (!settled) { settled = true; try { s.destroy(); } catch {} resolve(r); } };
    const timer = setTimeout(() => done({ ok: false, error: 'timeout awaiting response' }), timeout);
    s.on('error', (e) => { clearTimeout(timer); done({ ok: false, error: e.code || e.message }); });
    s.on('data', (c) => {
      buf += c.toString('latin1');
      if (mode === 'http' && buf.includes('\r\n\r\n')) { clearTimeout(timer); done({ ok: true, banner: buf }); }
      else if (mode !== 'http' && buf.length > 0) { clearTimeout(timer); done({ ok: true, banner: buf }); }
    });
    s.on('connect', () => {
      if (mode === 'http') s.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: KavachRecon/1.0 (+authorized-scan)\r\nConnection: close\r\n\r\n`);
      else if (mode === 'tls') { /* handled by tlsPro below via caller */ clearTimeout(timer); done({ ok: true, banner: '', tlsCandidate: true }); }
      // banner mode: wait for server banner
    });
    s.on('close', () => { clearTimeout(timer); done({ ok: buf.length > 0, banner: buf, error: buf.length ? undefined : 'no data' }); });
  });
}

export function tlsInspect(host, port = 443, servername, timeout = 6000) {
  return new Promise((resolve) => {
    const tryOnce = (minV, maxV, rejectUnauthorized) => new Promise((res) => {
      let s;
      try {
        s = tls.connect({ host, port, servername: servername || host, timeout, rejectUnauthorized, ...(minV ? { minVersion: minV } : {}), ...(maxV ? { maxVersion: maxV } : {}) }, () => {
        const cert = s.getPeerCertificate(true);
        const cipher = s.getCipher();
        const resObj = {
          ok: true, protocol: s.getProtocol(), cipher: cipher?.name, cipherVersion: cipher?.version,
          cert: cert ? {
            subject: cert.subject, issuer: cert.issuer, valid_from: cert.valid_from, valid_to: cert.valid_to,
            fingerprint256: cert.fingerprint256, subjectaltname: cert.subjectaltname, bits: cert.bits,
          } : null, chainLength: 0,
        };
        let c = cert; while (c && c.issuerCertificate && c.issuerCertificate.fingerprint256 !== c.fingerprint256) { resObj.chainLength++; c = c.issuerCertificate; }
        s.end(); res(resObj);
      });
        s.on('error', (e) => res({ ok: false, error: e.code || e.message, protocol: minV }));
        s.on('timeout', () => { try { s.destroy(); } catch {} res({ ok: false, error: 'timeout', protocol: minV }); });
      } catch (e) {
        res({ ok: false, error: e.code || e.message, protocol: minV });
      }
    });
    (async () => {
      try {
        const main = await tryOnce('TLSv1.2', null, true);
        if (main.ok) { resolve({ ...main, legacySupport: {} }); return; }
        const legacy10 = await tryOnce('TLSv1', 'TLSv1', false);
        const legacy11 = legacy10.ok ? { ok: false } : await tryOnce('TLSv1', 'TLSv1.1', false);
        if (legacy10.ok || legacy11.ok) resolve({ ok: true, protocol: legacy10.ok ? 'TLSv1' : 'TLSv1.1', legacySupport: { tls10: legacy10.ok, tls11: legacy11.ok }, legacyError: main.error, cert: null, cipher: null, chainLength: 0 });
        else resolve({ ok: false, error: main.error, legacySupport: { tls10: legacy10.ok, tls11: legacy11.ok } });
      } catch (e) {
        resolve({ ok: false, error: e.code || e.message, legacySupport: {} });
      }
    })();
  });
}

/** Fetch with redirect-chain capture, timeouts and size cap — records everything. */
export async function httpProbe(url, { timeout = 10000, maxRedirects = 8, method = 'GET', rateLimiter = null, host = null, maxBytes = 900_000, extraHeaders = {} } = {}) {
  const chain = [];
  let current = url;
  for (let i = 0; i <= maxRedirects; i++) {
    if (rateLimiter) { try { await rateLimiter.acquire(host || new URL(current).host); } catch {} }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(new Error('timeout')), timeout);
    try {
      const res = await fetch(current, {
        method, redirect: 'manual', signal: ctrl.signal,
        headers: { 'User-Agent': 'KavachRecon/1.0 (+authorized-recon; evidence-based)', 'Accept': '*/*', ...extraHeaders },
      });
      const headers = {};
      res.headers.forEach((v, k) => {
        headers[k] = headers[k] ? (Array.isArray(headers[k]) ? [...headers[k], v] : [headers[k], v]) : v;
      });
      const location = res.headers.get('location');
      if (location && [301, 302, 303, 307, 308].includes(res.status)) {
        chain.push({ url: current, status: res.status, location });
        current = new URL(location, current).href;
        clearTimeout(t); continue;
      }
      let body = '';
      if (method !== 'HEAD') {
        const reader = res.body?.getReader();
        if (reader) {
          const chunks = []; let total = 0;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value); total += value.length;
            if (total > maxBytes) { body += Buffer.concat(chunks).toString('utf8').slice(0, maxBytes); break; }
          }
          if (total <= maxBytes) body = Buffer.concat(chunks).toString('utf8');
        }
      }
      clearTimeout(t);
      return { ok: true, url, finalUrl: current, status: res.status, headers, body, chain, ms: null };
    } catch (e) {
      clearTimeout(t);
      const err = e?.cause?.code || e.message || 'error';
      return { ok: false, url, finalUrl: current, status: null, headers: {}, body: '', chain, error: String(err) };
    }
  }
  return { ok: true, url, finalUrl: current, status: 310, headers: {}, body: '', chain, error: 'too many redirects' };
}

export function parseTitle(html) {
  const m = html.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim() : null;
}

export function classifyHost(identifier) {
  if (net.isIPv4(identifier) || identifier.includes(':')) return 'IP';
  return 'DOMAIN';
}
