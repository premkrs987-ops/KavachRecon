// KavachRecon — deterministic, evidence-based findings rules.
// STRICT POLICY: discovery never automatically becomes a vulnerability.
// Only hard, verifiable evidence produces CONFIRMED_FINDING; everything else is
// OBSERVED / VERIFIED / INFERRED / HEURISTIC / MANUAL_REVIEW.
import { q, q1, now } from '../db.js';

function ev(rows) { return rows.map(r => r.evidence_id || r.id).filter(Boolean); }

export function deriveFindings(ctx) {
  const scanId = ctx.scan.id;
  const before = q(`SELECT COUNT(*) n FROM findings WHERE scan_id = ?`, [scanId])[0].n;

  certFindings(ctx);
  tlsFindings(ctx);
  headerFindings(ctx);
  cookieFindings(ctx);
  httpsRedirectFindings(ctx);
  emailSecurityFindings(ctx);
  danglingCnameFindings(ctx);
  exposedServiceFindings(ctx);
  endpointFindings(ctx);
  jsSecretFindings(ctx);
  interpretationFindings(ctx);

  return q(`SELECT COUNT(*) n FROM findings WHERE scan_id = ?`, [scanId])[0].n - before;
}

/* ---------- TLS / certificates ---------- */
function certFindings(ctx) {
  const rows = q(`SELECT * FROM posture WHERE scan_id = ? AND kind = 'CERT' AND state IN ('EXPIRED','EXPIRING_SOON')`, [ctx.scan.id]);
  for (const r of rows) {
    const expired = r.state === 'EXPIRED';
    ctx.store.addFinding({
      finding_key: `cert_${expired ? 'expired' : 'expiring'}_${r.url}`,
      title: expired ? `Expired TLS certificate presented by ${hostOf(r.url)}` : `TLS certificate for ${hostOf(r.url)} expires within 30 days`,
      category: 'TLS/CERTIFICATE',
      classification: 'VERIFIED',
      severity: expired ? 'HIGH' : 'MEDIUM',
      confidence: 'HIGH',
      asset_label: hostOf(r.url),
      description: expired
        ? `The service at ${r.url} presented a TLS certificate that is already expired (${r.value}). Verified from the live handshake.`
        : `The service at ${r.url} presented a TLS certificate expiring in less than 30 days (${r.value}). Verified from the live handshake.`,
      impact: expired ? 'Clients receive certificate errors; traffic may be intercepted by users overriding warnings.' : 'Risk of unplanned outage and client-side trust warnings if not renewed.',
      recommendation: expired ? 'Replace the expired certificate immediately and automate renewal.' : 'Confirm auto-renewal is functioning; renew before expiry.',
      evidence_ids: ev([r]),
      meta: { url: r.url },
    });
  }
}

function tlsFindings(ctx) {
  const rows = q(`SELECT * FROM posture WHERE scan_id = ? AND kind = 'TLS' AND state = 'WEAK_PROTOCOL'`, [ctx.scan.id]);
  for (const r of rows) {
    ctx.store.addFinding({
      finding_key: `tls_legacy_${r.url}`,
      title: `Legacy TLS protocol accepted by ${hostOf(r.url)}`,
      category: 'TLS/PROTOCOL',
      classification: 'CONFIRMED_FINDING',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      asset_label: hostOf(r.url),
      description: `A live TLS handshake with ${r.url} succeeded using a legacy protocol version (${r.header}). Confirmed by direct connection, not inferred.`,
      impact: 'Legacy TLS versions have known cryptographic weaknesses (e.g., POODLE, BEAST-family issues) and fail modern compliance baselines (PCI DSS, NIST SP 800-52).',
      recommendation: 'Disable TLSv1.0/1.1 on the endpoint and require TLSv1.2+ with modern ciphers.',
      evidence_ids: ev([r]),
      meta: { url: r.url },
    });
  }
}

/* ---------- security headers ---------- */
function headerFindings(ctx) {
  for (const kind of ['HSTS', 'CSP', 'XFO', 'XCTO', 'REFERRER', 'PERMISSIONS']) {
    const rows = q(`SELECT * FROM posture WHERE scan_id = ? AND kind = ? AND state = 'MISSING' AND url LIKE 'https:%'`, [ctx.scan.id, kind]);
    if (!rows.length) continue;
    const hosts = [...new Set(rows.map(r => hostOf(r.url)))];
    ctx.store.addFinding({
      finding_key: `header_missing_${kind}`,
      title: `Security header "${headerName(kind)}" not observed on ${hosts.length} HTTPS host${hosts.length > 1 ? 's' : ''}`,
      category: 'HTTP_SECURITY_HEADERS',
      classification: 'OBSERVED',
      severity: kind === 'CSP' ? 'LOW' : 'LOW',
      confidence: 'HIGH',
      asset_label: hosts.slice(0, 4).join(', ') + (hosts.length > 4 ? ` +${hosts.length - 4} more` : ''),
      description: `The ${headerName(kind)} response header was absent from actual HTTPS responses at ${rows.length} observed URL(s): ${rows.slice(0, 6).map(r => r.url).join(', ')}${rows.length > 6 ? ' …' : ''}. This is an observation about the collected responses — the header may be set on other paths or may have changed since collection.`,
      impact: impactForHeader(kind),
      recommendation: `Review whether ${headerName(kind)} should be enabled for these origins. Validate against application behaviour before changing configuration.`,
      evidence_ids: ev(rows.slice(0, 12)),
      meta: { kind, urls: rows.map(r => r.url).slice(0, 25) },
    });
  }
}
function headerName(kind) {
  return { HSTS: 'Strict-Transport-Security', CSP: 'Content-Security-Policy', XFO: 'X-Frame-Options', XCTO: 'X-Content-Type-Options', REFERRER: 'Referrer-Policy', PERMISSIONS: 'Permissions-Policy' }[kind] || kind;
}
function impactForHeader(kind) {
  return {
    HSTS: 'Users may be exposed to SSL-stripping/downgrade attacks on first visit.',
    CSP: 'Reduced defense-in-depth against cross-site scripting and content-injection.',
    XFO: 'Pages may be embedded in frames (clickjacking exposure).',
    XCTO: 'Browsers may MIME-sniff responses, enabling content-type confusion.',
    REFERRER: 'URLs and parameters may leak to third parties via the Referer header.',
    PERMISSIONS: 'Powerful browser features lack explicit policy restrictions.',
  }[kind] || '';
}

function cookieFindings(ctx) {
  const rows = q(`SELECT * FROM posture WHERE scan_id = ? AND kind = 'COOKIE' AND state = 'WEAK_FLAGS'`, [ctx.scan.id]);
  if (rows.length) {
    ctx.store.addFinding({
      finding_key: `cookies_weak_flags`,
      title: `Cookies observed without complete Secure/HttpOnly attributes (${rows.length} instance${rows.length > 1 ? 's' : ''})`,
      category: 'COOKIE_SECURITY',
      classification: 'OBSERVED',
      severity: 'LOW',
      confidence: 'HIGH',
      asset_label: hostOf(rows[0].url),
      description: `Set-Cookie responses at ${[...new Set(rows.map(r => r.url))].slice(0, 5).join(', ')} produced cookies lacking Secure and/or HttpOnly flags. Observation based on actual response headers.`,
      impact: 'Cookies without these flags are more exposed to interception or client-side access.',
      recommendation: 'Set Secure, HttpOnly and an explicit SameSite on all session cookies. Verify the application still functions.',
      evidence_ids: ev(rows.slice(0, 10)),
      meta: { count: rows.length },
    });
  }
}

function httpsRedirectFindings(ctx) {
  const rows = q(`SELECT * FROM posture WHERE scan_id = ? AND kind = 'HTTPS_REDIRECT' AND state = 'NOT_ENFORCED'`, [ctx.scan.id]);
  for (const r of rows) {
    ctx.store.addFinding({
      finding_key: `https_not_enforced_${r.url}`,
      title: `Plain-HTTP response observed without redirect to HTTPS on ${hostOf(r.url)}`,
      category: 'TRANSPORT_SECURITY',
      classification: 'OBSERVED',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      asset_label: hostOf(r.url),
      description: `${r.url} returned a successful response over plain HTTP without redirecting to HTTPS during probing.`,
      impact: 'Traffic served over HTTP can be read or modified in transit.',
      recommendation: 'Redirect all HTTP traffic to HTTPS and enable HSTS after verifying all subdomains support HTTPS.',
      evidence_ids: ev([r]),
      meta: { url: r.url },
    });
  }
}

/* ---------- email security (SPF/DMARC/DKIM) ---------- */
function emailSecurityFindings(ctx) {
  if (ctx.target.type !== 'DOMAIN') return; // SPF/DMARC apply to domains only
  const mods = q(`SELECT detail FROM scan_modules WHERE scan_id = ? AND module_key = 'email_security' AND status IN ('COMPLETED','COMPLETED_NO_RESULTS')`, [ctx.scan.id]);
  if (!mods.length) return;
  const domain = ctx.target.identifier;
  const has = (labelPart) => q1(`SELECT COUNT(*) n FROM dns_records WHERE scan_id = ? AND meta LIKE ?`, [ctx.scan.id, `%"label":%"${labelPart}%`]).n > 0 ||
    q(`SELECT meta FROM dns_records WHERE scan_id = ?`, [ctx.scan.id]).some(r => String(r.meta || '').includes(labelPart));
  const dmarc = q(`SELECT * FROM dns_records WHERE scan_id = ? AND name = ? AND value LIKE 'v=dmarc1%'`, [ctx.scan.id, `_dmarc.${domain}`]);
  const spf = q(`SELECT * FROM dns_records WHERE scan_id = ? AND name = ? AND value LIKE 'v=spf1%'`, [ctx.scan.id, domain]);
  if (!dmarc.length) {
    ctx.store.addFinding({
      finding_key: `email_dmarc_missing_${domain}`,
      title: `No DMARC policy record observed for ${domain}`,
      category: 'EMAIL_SECURITY',
      classification: 'OBSERVED',
      severity: 'LOW',
      confidence: 'MEDIUM',
      asset_label: domain,
      description: `A TXT query for _dmarc.${domain} returned no DMARC policy record at collection time. This is an observation about DNS state during the scan — DNS can change and some configurations publish policies on organisational parent domains.`,
      impact: 'Without DMARC, recipients receive no policy for handling spoofed mail from this domain.',
      recommendation: 'Confirm whether DMARC is intentionally absent; if the domain sends mail, publish a DMARC record (start with p=none + reporting, then tighten).',
      evidence_ids: [],
      meta: { query: `_dmarc.${domain} TXT` },
    });
  }
  if (!spf.length) {
    ctx.store.addFinding({
      finding_key: `email_spf_missing_${domain}`,
      title: `No SPF record observed for ${domain}`,
      category: 'EMAIL_SECURITY',
      classification: 'OBSERVED',
      severity: 'LOW',
      confidence: 'MEDIUM',
      asset_label: domain,
      description: `A TXT query for ${domain} returned no record beginning with v=spf1 at collection time. Observation only — the zone may delegate or simply not send mail.`,
      impact: 'Absence of SPF weakens sender verification for the domain.',
      recommendation: 'Verify mail posture for this domain; publish SPF if it sends or could be spoofed for sending.',
      evidence_ids: [],
      meta: { query: `${domain} TXT (v=spf1)` },
    });
  }
}

/* ---------- dangling CNAME ---------- */
function danglingCnameFindings(ctx) {
  const rows = q(`SELECT e.* FROM evidence e WHERE e.scan_id = ? AND e.kind = 'DNS_DANGLING_CNAME'`, [ctx.scan.id]);
  for (const r of rows) {
    ctx.store.addFinding({
      finding_key: `dangling_cname_${r.asset_id}`,
      title: `Dangling CNAME observed — manual verification required`,
      category: 'DNS_HYGIENE',
      classification: 'MANUAL_REVIEW',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      asset_id: r.asset_id,
      asset_label: assetLabel(r.asset_id),
      description: `${r.summary}. A CNAME whose target no longer resolves can, in some configurations, allow third parties to claim the underlying service (subdomain takeover). Whether takeover is actually possible depends on the target service — it could NOT be confirmed from passive evidence.`,
      impact: 'If the target service can be re-registered by a third party, attacker-controlled content could be served from the trusted domain.',
      recommendation: 'Verify the CNAME target with the responsible team; remove or re-point stale records. Attempt takeover validation only with written authorisation.',
      evidence_ids: [r.id],
      meta: {},
    });
  }
}

/* ---------- exposed services ---------- */
const SENSITIVE_SERVICES = { mysql: 'MySQL', postgresql: 'PostgreSQL', redis: 'Redis', mongodb: 'MongoDB', memcached: 'Memcached', elasticsearch: 'Elasticsearch', rdp: 'RDP', telnet: 'Telnet', ftp: 'FTP', smtp: 'SMTP', mssql: 'MS SQL', rabbitmq_mgmt: 'RabbitMQ management', kibana: 'Kibana', docker: 'Docker API', hadoop: 'Hadoop' };
function isPrivateIp(ip) {
  if (!ip || ip === '127.0.0.1' || ip.startsWith('127.')) return true;
  return ['10.', '192.168.', '169.254.', 'fc', 'fd', 'fe80'].some(p => ip.startsWith(p)) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}
function exposedServiceFindings(ctx) {
  const rows = q(`SELECT * FROM host_ports WHERE scan_id = ? AND state = 'OPEN' AND service IS NOT NULL`, [ctx.scan.id]);
  for (const r of rows) {
    const svcName = SENSITIVE_SERVICES[r.service?.toLowerCase()];
    if (!svcName) continue;
    const publicHost = !isPrivateIp(r.ip);
    ctx.store.addFinding({
      finding_key: `service_exposed_${r.ip}_${r.port}`,
      title: `${svcName} service confirmed listening on ${r.host}:${r.port}${publicHost ? '' : ' (non-public address)'}`,
      category: 'NETWORK_EXPOSURE',
      classification: 'HEURISTIC',
      severity: publicHost ? 'MEDIUM' : 'LOW',
      confidence: 'HIGH',
      asset_label: `${r.host}:${r.port}`,
      description: `A confirmed-open ${svcName} service was observed at ${r.host}:${r.port} during the authorized scan${r.banner ? ` (banner evidence: "${r.banner.slice(0, 120).replace(/\n/g, ' ')}")` : ''}. Whether this exposure is intended (e.g., internal tooling, restricted by firewall ACL) could not be determined from scan data alone.`,
      impact: publicHost ? 'Datastore/management services exposed to untrusted networks are a common initial-access vector.' : 'Internal service reachable from the scanning vantage point; verify intended audience.',
      recommendation: 'Verify with the asset owner that this listener is intentional and access-restricted. Enforce authentication, network ACLs and encryption.',
      evidence_ids: [r.evidence_id].filter(Boolean),
      meta: { port: r.port, service: r.service, ip: r.ip },
    });
  }
  const unverified = q(`SELECT * FROM host_ports WHERE scan_id = ? AND state = 'OPEN_UNVERIFIED'`, [ctx.scan.id]);
  if (unverified.length) {
    ctx.store.addFinding({
      finding_key: `ports_unverified`,
      title: `${unverified.length} TCP connect(s) accepted without a confirming service response`,
      category: 'NETWORK_OBSERVATION',
      classification: 'OBSERVED',
      severity: 'INFO',
      confidence: 'MEDIUM',
      asset_label: [...new Set(unverified.map(u => `${u.host}:${u.port}`))].slice(0, 5).join(', ') + (unverified.length > 5 ? ` +${unverified.length - 5}` : ''),
      description: `TCP connections were accepted on ${unverified.length} host/port combination(s) but no service banner or protocol response was received, so the service identity is UNCONFIRMED. These are recorded as OPEN_UNVERIFIED and are not counted as confirmed services. Accepted connects can also be an artefact of transparent network middleboxes.`,
      impact: 'Unknown listeners may exist behind these ports.',
      recommendation: 'Re-verify these ports from a network vantage point with full egress; confirm with host owners.',
      evidence_ids: ev(unverified.slice(0, 15)),
      meta: { count: unverified.length },
    });
  }
}

/* ---------- endpoints ---------- */
function endpointFindings(ctx) {
  const adminRows = q(`SELECT * FROM endpoints WHERE scan_id = ? AND classification = 'ADMIN' AND status_code IS NOT NULL AND status_code < 400`, [ctx.scan.id]);
  for (const r of adminRows.slice(0, 20)) {
    ctx.store.addFinding({
      finding_key: `endpoint_admin_${r.url}`,
      title: `Potential administrative endpoint observed — manual verification required`,
      category: 'WEB_EXPOSURE',
      classification: 'MANUAL_REVIEW',
      severity: 'MEDIUM',
      confidence: 'LOW',
      asset_id: r.asset_id,
      asset_label: r.url,
      description: `${r.url} responded with HTTP ${r.status_code} during probing and its path pattern classifies as administrative. This is a path-based classification ONLY — the actual function of the endpoint (real admin panel vs. generic app route vs. soft-404) was not verified and MUST be reviewed manually before any conclusion is drawn.`,
      impact: 'If this is a genuine, unauthenticated administrative interface, it may allow privileged actions.',
      recommendation: `Open ${r.url} in an authorised review, confirm the application behind it, and check authentication requirements. Do not treat this as a vulnerability until verified.`,
      evidence_ids: [r.evidence_id].filter(Boolean),
      meta: { url: r.url, status: r.status_code },
    });
  }
  const sensitiveRows = q(`SELECT * FROM endpoints WHERE scan_id = ? AND classification = 'POTENTIALLY_SENSITIVE' AND status_code IS NOT NULL AND status_code = 200`, [ctx.scan.id]);
  for (const r of sensitiveRows.slice(0, 20)) {
    ctx.store.addFinding({
      finding_key: `endpoint_sensitive_${r.url}`,
      title: `Potentially sensitive path returned HTTP 200 — content verification required`,
      category: 'WEB_EXPOSURE',
      classification: 'MANUAL_REVIEW',
      severity: 'HIGH',
      confidence: 'LOW',
      asset_id: r.asset_id,
      asset_label: r.url,
      description: `${r.url} returned HTTP 200. Its path pattern matches potentially sensitive patterns (e.g., VCS metadata, environment files, backups). The response BODY was not security-reviewed by this rule; a 200 can also be a soft-404 or a generic SPA catch-all route.`,
      impact: 'If genuine, such files can leak source code, credentials or configuration.',
      recommendation: `Manually inspect the response content of ${r.url}. Confirm whether it is a real exposure or a soft-404 before classifying.`,
      evidence_ids: [r.evidence_id].filter(Boolean),
      meta: { url: r.url, status: r.status_code },
    });
  }
}

/* ---------- JS secrets ---------- */
function jsSecretFindings(ctx) {
  const all = q(`SELECT s.*, r.url AS js_url FROM js_secrets s JOIN js_resources r ON r.id = s.js_id WHERE r.scan_id = ? AND s.dismissed = 0`, [ctx.scan.id]);
  for (const r of all) {
    const verified = !!r.verified;
    const sevByKind = r.kind.includes('Stripe') || r.kind.includes('PRIVATE KEY') ? 'CRITICAL' : (r.kind.includes('AWS') || r.kind.includes('Google API') || r.kind.includes('GitHub') ? 'HIGH' : 'MEDIUM');
    ctx.store.addFinding({
      finding_key: `js_secret_${r.id}`,
      title: `${verified ? 'Verified' : 'Unverified'} potential secret in JavaScript: ${r.kind}`,
      category: 'SECRET_EXPOSURE',
      classification: verified ? 'CONFIRMED_FINDING' : 'MANUAL_REVIEW',
      severity: verified ? sevByKind : (r.confidence === 'HIGH' ? sevByKind : 'MEDIUM'),
      confidence: verified ? 'HIGH' : r.confidence === 'HIGH' ? 'MEDIUM' : 'LOW',
      asset_label: r.js_url,
      description: `${verified ? 'A human analyst has VERIFIED' : 'A pattern scan found'} a potential ${r.kind} in ${r.js_url}. Redacted match: ${r.match_redacted}. ${verified ? 'The credential is confirmed present in the fetched asset.' : 'This is a REGEX PATTERN MATCH ONLY — the full value was never stored and the finding requires human verification (it may be an example/test/dummy value).'}`,
      impact: verified ? 'Confirmed credential exposure in a publicly fetched asset; treat as a credential compromise.' : 'If genuine, the credential could allow access to the related service.',
      recommendation: verified ? 'Revoke and rotate the credential immediately; purge from source control and rebuild the asset.' : `Open ${r.js_url}, locate the pattern, and determine if it is a real credential. Mark verified/rejected in KavachRecon.`,
      evidence_ids: [r.evidence_id].filter(Boolean),
      meta: { js_id: r.js_id, secret_id: r.id, kind: r.kind },
    });
  }
}

/* ---------- interpretation aids (explicitly informational) ---------- */
function interpretationFindings(ctx) {
  const mod = q1(`SELECT detail FROM scan_modules WHERE scan_id = ? AND module_key = 'dns_analysis'`, [ctx.scan.id]);
  if (mod?.detail) {
    let d; try { d = JSON.parse(mod.detail); } catch { d = {}; }
    if (d.wildcard_present) {
      ctx.store.addFinding({
        finding_key: `dns_wildcard_${ctx.target.identifier}`,
        title: `Wildcard DNS behaviour present for ${ctx.target.identifier} (informational)`,
        category: 'DNS_INTERPRETATION',
        classification: 'OBSERVED',
        severity: 'INFO',
        confidence: 'HIGH',
        asset_label: ctx.target.identifier,
        description: `Random-label probes resolved, indicating wildcard DNS for this zone. NOTE: this is NOT a vulnerability. It matters for interpretation: every "resolved" subdomain in this scan should be sanity-checked, because non-existent names may also resolve.`,
        impact: 'Informational — affects interpretation of subdomain discovery results.',
        recommendation: 'Keep in mind when triaging subdomain results; no action required.',
        evidence_ids: [],
        meta: {},
      });
    }
  }
}

function hostOf(url) { try { return new URL(url).host; } catch { return url; } }
function assetLabel(id) {
  if (!id) return '';
  const a = q1(`SELECT key FROM assets WHERE id = ?`, [id]);
  return a?.key || id;
}
