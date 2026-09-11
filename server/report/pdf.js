// KavachRecon — professional PDF report (pdfkit). Contains ONLY actual collected/derived data.
import PDFDocument from 'pdfkit';
import { q, q1 } from '../db.js';
import { buildSummary } from '../scanner/engine.js';

const C = {
  ink: '#101828', sub: '#475467', faint: '#98a2b3', line: '#e4e7ec',
  brand: '#0f2a43', brand2: '#123a5c', accent: '#0e9384', accentDark: '#0b6e63',
  bg: '#f7f9fc', chipBg: '#eef4f8',
  crit: '#b42318', high: '#d92d20', med: '#dc6803', low: '#175cd3', info: '#475467', ok: '#067647',
  headFill: '#0f2a43', rowAlt: '#f4f7fa',
};

const SEV_COLOR = { CRITICAL: C.crit, HIGH: C.high, MEDIUM: C.med, LOW: C.low, INFO: C.info };

export async function generateScanReport(scanId, res) {
  const scan = q1(`SELECT * FROM scans WHERE id = ?`, [scanId]);
  if (!scan) throw new Error('scan not found');
  const target = q1(`SELECT * FROM targets WHERE id = ?`, [scan.target_id]);
  const workspace = q1(`SELECT * FROM workspaces WHERE id = ?`, [scan.workspace_id]);
  const creator = scan.created_by ? q1(`SELECT name, email FROM users WHERE id = ?`, [scan.created_by]) : null;

  const doc = new PDFDocument({ size: 'A4', margins: { top: 64, bottom: 64, left: 48, right: 48 }, bufferPages: true, info: { Title: `KavachRecon Report — ${scan.name}`, Author: '@premkrs', Subject: `Authorized reconnaissance of ${target.identifier}` } });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="KavachRecon_${sanitize(scan.name)}_${scanId.slice(-8)}.pdf"`);
  doc.pipe(res);

  const R = new Renderer(doc);
  const summary = JSON.parse(scan.summary || '{}') || buildSummary(scan.workspace_id, scanId);

  /* ============ COVER ============ */
  R.coverPage({ scan, target, workspace, creator });

  /* ============ TOC ============ */
  R.pageHeader('Contents');
  R.h1('Report Contents');
  const toc = [
    ['1', 'Executive Summary'], ['2', 'Scope & Authorisation'], ['3', 'Scan Methodology'],
    ['4', 'Module Execution Matrix'], ['5', 'Asset Inventory'], ['6', 'DNS Intelligence'],
    ['7', 'Network Intelligence'], ['8', 'Web Intelligence'], ['9', 'Endpoint Intelligence'],
    ['10', 'JavaScript Intelligence'], ['11', 'Technology & Perimeter'], ['12', 'Security Posture'],
    ['13', 'Findings (Confirmed & Classified)'], ['14', 'Manual Review / Heuristic Items'],
    ['15', 'Scan Comparison'], ['16', 'Limitations & Coverage Gaps'], ['17', 'Evidence Appendix'],
  ];
  R.list(toc.map(([n, t]) => `${n}.  ${t}`), { gap: 4 });
  R.spacer(14);
  R.callout('Read-first', 'This report contains ONLY data actually collected during the authorized scan. Where modules failed or were skipped, coverage is explicitly limited: absence of data is never presented as absence of risk. Observations are labelled and separated from confirmed findings.', 'info');

  /* ============ 1. EXECUTIVE SUMMARY ============ */
  R.pageHeader('Executive Summary');
  R.h1('1. Executive Summary');
  R.meta(`Generated ${new Date().toISOString().replace('T', ' ').slice(0, 16)} UTC • Scan "${scan.name}" • Target ${target.identifier}`);
  const t = summary.totals || {};
  R.statGrid([
    ['Assets in inventory', t.assets ?? 0], ['Live hosts', t.live_hosts ?? 0],
    ['Subdomains', t.subdomains ?? 0], ['IP addresses', t.ips ?? 0],
    ['Open ports', t.open_ports ?? 0], ['Distinct services', t.services ?? 0],
    ['Web responses', t.web_apps ?? 0], ['Endpoints', t.endpoints ?? 0],
    ['Technologies', t.technologies ?? 0], ['DNS records', t.dns_records ?? 0],
    ['Findings (all classes)', t.findings ?? 0], ['Review items', t.review_items ?? 0],
  ]);
  R.h2('Risk distribution (findings recorded in this scan)');
  const sevRows = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => [s, String(summary.severity?.[s] ?? 0)]);
  R.table([{ key: 0, label: 'Severity', width: 160 }, { key: 1, label: 'Findings', width: 80, align: 'right' }], sevRows, { sevColor: (v) => SEV_COLOR[v] });
  R.h2('Important limitations');
  const failedMods = q(`SELECT name, error FROM scan_modules WHERE scan_id = ? AND status = 'FAILED'`, [scanId]);
  const skippedMods = q(`SELECT name, detail FROM scan_modules WHERE scan_id = ? AND status IN ('SKIPPED','NOT_APPLICABLE')`, [scanId]);
  if (failedMods.length) {
    R.para(`This scan completed WITH MODULE FAILURES. ${failedMods.length} module(s) failed; for the areas they cover, exposure could not be fully determined. No statement of "no findings" is made for those areas.`);
    R.bullets(failedMods.map(m => `${m.name}: failed${m.error ? ` — ${String(m.error).slice(0, 140)}` : ''}`));
  } else if (skippedMods.length) {
    R.para(`All executed modules returned data-collection results. ${skippedMods.length} module(s) were skipped/not applicable (see §4); conclusions are limited to the areas actually covered.`);
  } else {
    R.para('All configured modules completed with results or explicitly reported no results. Conclusions are limited to the scope, vantage point and time window of this scan.');
  }
  R.para('Method note: discovery is not confirmation. Items classified OBSERVED, HEURISTIC or MANUAL_REVIEW require human verification and are listed separately from confirmed findings (§13 vs §14).', { color: C.sub });

  /* ============ 2. SCOPE ============ */
  R.pageHeader('Scope & Authorisation');
  R.h1('2. Scope & Authorisation');
  R.kvTable([
    ['Authorized target', `${target.identifier} (${target.type})`],
    ['Workspace', workspace.name],
    ['Scan name', scan.name],
    ['Scan mode', scan.mode === 'ACTIVE_CONFIRMED' ? 'ACTIVE (operator-confirmed)' : 'PASSIVE-ONLY (no active probing)'],
    ['Scan started', scan.started_at || '—'], ['Scan finished', scan.finished_at || '—'],
    ['Scan ID', scan.id],
  ]);
  const scopeRules = q(`SELECT kind, pattern, pattern_type, reason FROM scope_rules WHERE target_id = ?`, [target.id]);
  if (scopeRules.length) {
    R.h2('Scope rules');
    R.table([
      { key: 0, label: 'Kind', width: 70 }, { key: 1, label: 'Pattern', width: 150 },
      { key: 2, label: 'Type', width: 80 }, { key: 3, label: 'Reason', width: 200 },
    ], scopeRules.map(r => [r.kind, r.pattern, r.pattern_type, r.reason || '—']));
  }
  R.para('Scope enforcement: every network operation performed by the engine was validated against the rules above before execution; out-of-scope references discovered in data were recorded but never contacted.', { color: C.sub });
  R.h2('Scan configuration');
  R.code(JSON.stringify(JSON.parse(scan.config || '{}'), null, 1).slice(0, 1200));

  /* ============ 3. METHODOLOGY ============ */
  R.pageHeader('Scan Methodology');
  R.h1('3. Scan Methodology');
  R.para('KavachRecon executed the modules listed in §4 in sequence. Passive modules use only public data sources and DNS; active modules (network probing, HTTP requests, TLS handshakes) ran only because this scan was created in ACTIVE mode with explicit operator confirmation. Data sources actually used include: the configured DNS resolvers, public Certificate Transparency log search (crt.sh), RDAP directory, classic WHOIS (TCP/43), Team Cymru IP-to-ASN, Internet Archive CDX, and direct TCP/HTTP/TLS probes to in-scope assets. Anything unreachable is recorded as a failure, not as an absence.');
  R.kvTable([
    ['Collection window', `${(scan.started_at || '').replace('T', ' ').slice(0, 19)} → ${(scan.finished_at || '').replace('T', ' ').slice(0, 19)} UTC`],
    ['Evidence records', String(summary.totals?.evidence ?? 0)],
    ['Rate controls', 'Token-bucket limiter (global + per-host), bounded concurrency, per-module timeouts'],
    ['Engine', 'KavachRecon v1.0 (built by @premkrs)'],
  ]);

  /* ============ 4. MODULE MATRIX ============ */
  R.pageHeader('Module Execution Matrix');
  R.h1('4. Module Execution Matrix');
  const mods = q(`SELECT * FROM scan_modules WHERE scan_id = ? ORDER BY order_idx`, [scanId]);
  const modRows = mods.map(m => [m.name, m.status, String(m.items_count || 0), m.duration_ms ? `${(m.duration_ms / 1000).toFixed(1)}s` : '—']);
  R.table([
    { key: 0, label: 'Module', width: 220 }, { key: 1, label: 'Status', width: 130 }, { key: 2, label: 'Items', width: 50, align: 'right' }, { key: 3, label: 'Time', width: 50, align: 'right' },
  ], modRows, { statusColor: (v) => moduleStatusColor(v) });
  R.spacer(6);
  R.para('Status legend: COMPLETED (data collected) • COMPLETED_NO_RESULTS (module ran fine, source legitimately returned nothing) • FAILED (data could NOT be collected — no conclusions possible for that area) • SKIPPED / NOT_APPLICABLE (not run, reason recorded) • QUEUED/RUNNING (timing artefact).', { size: 8.5, color: C.sub });
  const failedDetails = mods.filter(m => m.status === 'FAILED');
  if (failedDetails.length) {
    R.h2('Failure detail');
    R.bullets(failedDetails.map(m => `${m.name}: ${String(m.error || 'unknown error').slice(0, 220)}`));
  }

  /* ============ 5. ASSET INVENTORY ============ */
  R.pageHeader('Asset Inventory');
  R.h1('5. Asset Inventory');
  const assetTypes = q(`SELECT type, COUNT(*) n FROM assets WHERE workspace_id = ? AND verification != 'FALSE_POSITIVE' GROUP BY type ORDER BY n DESC`, [scan.workspace_id]);
  R.para(`Inventory is workspace-level and de-duplicated (first-seen/last-seen tracked). Relationship edges connect domains → subdomains → IPs → ports → services → URLs → endpoints → technologies.`);
  R.table([{ key: 0, label: 'Asset type', width: 200 }, { key: 1, label: 'Count', width: 70, align: 'right' }], assetTypes.map(a => [a.type, String(a.n)]));
  for (const [label, type, cap] of [['Domains & subdomains', "('DOMAIN','SUBDOMAIN')", 60], ['IP addresses & hosts', "('IP','HOST','CIDR')", 50]]) {
    const rows = q(`SELECT key, value, status, origin, confidence, first_seen, last_seen FROM assets WHERE workspace_id = ? AND type IN ${type} AND verification != 'FALSE_POSITIVE' ORDER BY first_seen LIMIT ${cap}`, [scan.workspace_id]);
    if (!rows.length) continue;
    R.h2(label);
    R.table([
      { key: 0, label: 'Asset', width: 180 }, { key: 1, label: 'Status', width: 70 },
      { key: 2, label: 'Conf.', width: 45 }, { key: 3, label: 'First seen (UTC)', width: 85 }, { key: 4, label: 'Last seen (UTC)', width: 85 },
    ], rows.map(r => [r.key, r.status, r.confidence?.[0] + r.confidence?.slice(1).toLowerCase(), (r.first_seen || '').replace('T', ' ').slice(0, 16), (r.last_seen || '').replace('T', ' ').slice(0, 16)]));
  }
  const edgeCount = q1(`SELECT COUNT(*) n FROM asset_edges WHERE workspace_id = ?`, [scan.workspace_id]).n;
  R.para(`Relationships recorded: ${edgeCount} edges. Full graph is available in the platform (Attack-Surface Graph view) and in the JSON export.`, { color: C.sub });

  /* ============ 6. DNS ============ */
  R.pageHeader('DNS Intelligence');
  R.h1('6. DNS Intelligence');
  const dnsRows = q(`SELECT * FROM dns_records WHERE scan_id = ? ORDER BY type, name`, [scanId]);
  if (dnsRows.length) {
    const byType = {};
    dnsRows.forEach(r => { (byType[r.type] = byType[r.type] || []).push(r); });
    for (const [type, rows] of Object.entries(byType)) {
      R.h2(`${type} records (${rows.length})`);
      if (type === 'PTR' || type === 'SOA' || type === 'TXT') {
        R.bullets(rows.slice(0, 25).map(r => `${r.name} → ${String(r.value).slice(0, 220)}`));
      } else {
        R.table([
          { key: 0, label: 'Name', width: 190 }, { key: 1, label: 'Value', width: 200 },
        ], rows.slice(0, 30).map(r => [r.name, String(r.value).slice(0, 180)]));
      }
    }
    const dnsMod = q1(`SELECT detail FROM scan_modules WHERE scan_id = ? AND module_key = 'dns_analysis'`, [scanId]);
    if (dnsMod?.detail) {
      const d = JSON.parse(dnsMod.detail);
      R.h2('DNS behaviour analysis');
      R.bullets([
        `Wildcard DNS: ${d.wildcard_present ? 'PRESENT (random labels resolve — subdomain results should be interpreted with this in mind). This is an observation, not a vulnerability.' : 'not detected in A-record probes'}`,
        `Dangling CNAME candidates: ${d.dangling_cnames ?? 0} (each requires manual verification; see §14)`,
      ]);
    }
  } else {
    const dnsMod = q1(`SELECT status, error FROM scan_modules WHERE scan_id = ? AND module_key = 'dns_enum'`, [scanId]);
    if (dnsMod?.status === 'FAILED') R.callout('Data unavailable', `DNS enumeration FAILED (${dnsMod.error || 'unknown error'}). No DNS records were collected; no conclusions about the zone can be drawn from this report.`, 'warn');
    else R.para('No DNS records were collected by this scan (module completed without results).');
  }

  /* ============ 7. NETWORK ============ */
  R.pageHeader('Network Intelligence');
  R.h1('7. Network Intelligence');
  const psMod = q1(`SELECT status FROM scan_modules WHERE scan_id = ? AND module_key = 'port_scan'`, [scanId]);
  if (scan.mode !== 'ACTIVE_CONFIRMED') {
    R.callout('Passive scan', 'This scan ran in PASSIVE-ONLY mode: no network probing was performed, so open/closed/filtered port states were NOT determined. Listing ports here would be fabricated; run an authorized active scan to populate this section.', 'info');
  } else {
    const portRows = q(`SELECT * FROM host_ports WHERE scan_id = ? ORDER BY host, port`, [scanId]);
    if (portRows.length) {
      const open = portRows.filter(p => p.state === 'OPEN');
      const unv = portRows.filter(p => p.state === 'OPEN_UNVERIFIED');
      R.para(`${open.length} confirmed-open port(s), ${unv.length} accepted-but-unverified TCP connect(s), ${portRows.length - open.length - unv.length} closed/filtered results.`);
      if (open.length) {
        R.h2('Confirmed open services');
        R.table([
          { key: 0, label: 'Host', width: 130 }, { key: 1, label: 'Port/Proto', width: 60 },
          { key: 2, label: 'Service', width: 90 }, { key: 3, label: 'Banner / version (as detected)', width: 170 },
        ], open.slice(0, 40).map(p => [`${p.host} (${p.ip})`, `${p.port}/tcp`, p.service || '—', (p.banner || p.version || 'no banner captured').replace(/\s+/g, ' ').slice(0, 90)]));
      }
      if (unv.length) {
        R.h2('Unverified TCP accepts');
        R.bullets(unv.slice(0, 15).map(p => `${p.host}:${p.port}/tcp — connect accepted, no service response (identity UNCONFIRMED)`));
      }
    } else if (psMod?.status === 'FAILED') {
      R.callout('Data unavailable', 'Port scanning FAILED. No port states were determined for this scan.', 'warn');
    } else {
      R.para('No live hosts were available to the port-scanning module (see §4). Port states were not determined.');
    }
  }

  /* ============ 8. WEB ============ */
  R.pageHeader('Web Intelligence');
  R.h1('8. Web Intelligence');
  const webRows = q(`SELECT * FROM web_observations WHERE scan_id = ? AND ok = 1 ORDER BY url`, [scanId]);
  if (webRows.length) {
    for (const w of webRows.slice(0, 25)) {
      const headers = JSON.parse(w.headers || '{}');
      R.h2(w.url, { size: 11 });
      const chain = JSON.parse(w.redirect_chain || '[]');
      R.kvTable([
        ['Status', String(w.status_code ?? '—')],
        ['Final URL', w.final_url || '—'],
        ['Redirect chain', chain.length ? chain.map(c => `${c.status} → ${c.location}`).join('  ⇒  ') : 'none observed'],
        ['Page title', w.title || '(none in markup)'],
        ['Server header', w.server || '(absent)'],
        ['Content-Type', w.content_type || '(absent)'],
        ['TLS', w.tls ? tlsBrief(w.tls) : '—'],
        ['Security headers', headerBrief(headers)],
      ]);
    }
  } else {
    R.callout('Data unavailable', 'No HTTP/HTTPS service responded to probing in this environment. Web intelligence sections (8–12) could not be populated — this is a data-collection limitation, NOT evidence that no web applications exist.', 'warn');
  }

  /* ============ 9. ENDPOINTS ============ */
  R.pageHeader('Endpoint Intelligence');
  R.h1('9. Endpoint Intelligence');
  const epRows = q(`SELECT * FROM endpoints WHERE scan_id = ? ORDER BY classification, url`, [scanId]);
  if (epRows.length) {
    const groups = {};
    epRows.forEach(e => { (groups[e.classification] = groups[e.classification] || []).push(e); });
    R.para(`Classifications are pattern-based and evidence-linked; a classification is NOT a vulnerability. Paths of interest (ADMIN / POTENTIALLY_SENSITIVE) appear in §14 for manual verification.`);
    for (const [cls, rows] of Object.entries(groups)) {
      R.h2(`${cls} (${rows.length})`);
      R.table([
        { key: 0, label: 'URL', width: 260 }, { key: 1, label: 'HTTP', width: 40, align: 'right' }, { key: 2, label: 'Note', width: 150 },
      ], rows.slice(0, 40).map(r => [r.url.length > 78 ? r.url.slice(0, 75) + '…' : r.url, r.status_code ?? '—', (r.note || '').slice(0, 80)]));
      if (rows.length > 40) R.para(`…and ${rows.length - 40} more (see CSV/JSON exports).`, { size: 8.5, color: C.faint });
    }
  } else {
    R.para('No endpoints were discovered from reachable pages or sitemaps in this scan. Where the page-crawl modules could not run (failed probing), endpoint coverage is correspondingly incomplete.');
  }

  /* ============ 10. JS INTEL ============ */
  R.pageHeader('JavaScript Intelligence');
  R.h1('10. JavaScript Intelligence');
  const jsRows = q(`SELECT r.*, (SELECT COUNT(*) FROM js_routes rt WHERE rt.js_id = r.id) routes, (SELECT COUNT(*) FROM js_secrets s WHERE s.js_id = r.id AND s.dismissed = 0) secrets FROM js_resources r WHERE r.scan_id = ?`, [scanId]);
  if (jsRows.length) {
    R.table([
      { key: 0, label: 'JavaScript resource', width: 230 }, { key: 1, label: 'Fetched', width: 45 }, { key: 2, label: 'Routes', width: 40, align: 'right' }, { key: 3, label: 'Potential secrets', width: 80, align: 'right' },
    ], jsRows.slice(0, 30).map(r => [r.url.length > 70 ? r.url.slice(0, 67) + '…' : r.url, r.fetched_ok ? 'yes' : 'no', String(r.routes), String(r.secrets)]));
    const routeRows = q(`SELECT rt.route, rt.kind, r.url FROM js_routes rt JOIN js_resources r ON r.id = rt.js_id WHERE r.scan_id = ? LIMIT 60`, [scanId]);
    if (routeRows.length) {
      R.h2(`API routes / endpoint references (${routeRows.length})`);
      R.bullets(routeRows.slice(0, 40).map(r => `[${r.kind}] ${r.route}  —  in ${r.url.split('/').pop() || r.url}`));
    }
    const secretRows = q(`SELECT s.kind, s.match_redacted, s.verified, s.confidence, r.url FROM js_secrets s JOIN js_resources r ON r.id = s.js_id WHERE r.scan_id = ? AND s.dismissed = 0`, [scanId]);
    if (secretRows.length) {
      R.h2('Potential secrets (REDACTED, unverified unless stated)');
      R.bullets(secretRows.slice(0, 30).map(s => `${s.kind} — ${s.match_redacted} — ${s.verified ? 'VERIFIED by analyst' : 'UNVERIFIED pattern match'} — ${s.confidence} confidence — in ${s.url}`));
      R.para('Potential secrets are regex matches with the full value intentionally NOT stored. They require human verification; see §14.', { color: C.sub });
    }
  } else {
    R.para('No JavaScript resources were collected (either no pages were reachable or none referenced external scripts). No JS-exposure conclusions can be drawn from this scan.');
  }

  /* ============ 11. TECH & PERIMETER ============ */
  R.pageHeader('Technology & Perimeter');
  R.h1('11. Technology & Perimeter');
  const techRows = q(`SELECT * FROM technologies WHERE scan_id = ? ORDER BY category, name`, [scanId]);
  if (techRows.length) {
    R.h2(`Technologies (${techRows.length}) — evidence-backed only`);
    R.table([
      { key: 0, label: 'Technology', width: 130 }, { key: 1, label: 'Version', width: 70 },
      { key: 2, label: 'Detection method', width: 120 }, { key: 3, label: 'Evidence match', width: 130 }, { key: 4, label: 'Conf.', width: 45 },
    ], techRows.slice(0, 40).map(r => [r.name, r.version || '—', r.detection_method, (r.raw_match || '').slice(0, 60), r.confidence]));
  } else {
    R.para('No technology signatures matched collected evidence. (Where HTTP collection failed entirely, this section could not be evaluated.)');
  }
  const perimRows = q(`SELECT * FROM perimeter WHERE scan_id = ? ORDER BY kind`, [scanId]);
  if (perimRows.length) {
    R.h2(`Perimeter / edge infrastructure (${perimRows.length})`);
    R.table([
      { key: 0, label: 'Kind', width: 70 }, { key: 1, label: 'Name', width: 110 }, { key: 2, label: 'Detection method', width: 150 }, { key: 3, label: 'Raw match', width: 110 }, { key: 4, label: 'Conf.', width: 40 },
    ], perimRows.slice(0, 30).map(r => [r.kind, r.name, r.detection_method, (r.raw_match || '').slice(0, 50), r.confidence]));
  } else {
    R.para('No CDN/WAF/proxy signatures matched the collected evidence. NOTE: this must not be read as "no WAF or CDN exists" — detection depends on reachable responses and matching signatures.');
  }

  /* ============ 12. SECURITY POSTURE ============ */
  R.pageHeader('Security Posture');
  R.h1('12. Security Posture');
  const posRows = q(`SELECT * FROM posture WHERE scan_id = ? ORDER BY url, kind`, [scanId]);
  if (posRows.length) {
    const urls = [...new Set(posRows.map(p => p.url))].slice(0, 15);
    for (const url of urls) {
      const rows = posRows.filter(p => p.url === url);
      R.h2(url, { size: 10.5 });
      R.table([
        { key: 0, label: 'Check', width: 110 }, { key: 1, label: 'State', width: 90 }, { key: 2, label: 'Observed value', width: 250 },
      ], rows.map(r => [r.kind + (r.header && r.kind !== 'TLS' && r.kind !== 'CERT' && r.kind !== 'HTTPS_REDIRECT' && r.kind !== 'COOKIE' ? '' : ''), r.state.replace(/_/g, ' '), (r.value || r.header || '(absent)').slice(0, 110)], { stateColor: (v) => postureColor(v) }));
    }
  } else {
    R.callout('Data unavailable', 'No HTTP responses were available to assess security posture. No posture conclusions can be drawn from this scan.', 'warn');
  }

  /* ============ 13. FINDINGS ============ */
  R.pageHeader('Findings');
  R.h1('13. Findings');
  const findings = q(`SELECT * FROM findings WHERE scan_id = ? ORDER BY risk_score DESC`, [scanId]);
  const confirmed = findings.filter(f => ['CONFIRMED_FINDING', 'VERIFIED'].includes(f.classification));
  const observed = findings.filter(f => f.classification === 'OBSERVED');
  if (confirmed.length) {
    R.para(`${confirmed.length} finding(s) reached CONFIRMED/VERIFIED classification. Every finding links to its evidence IDs (§17).`);
    confirmed.forEach((f, i) => {
      R.findingBlock(f, i + 1);
    });
  } else {
    const failedCount = failedMods.length;
    R.callout('No confirmed finding', failedCount
      ? `No confirmed finding was established from the available evidence. Certain modules failed or were incomplete; therefore exposure could not be fully determined for those areas.`
      : `No confirmed finding was established from the available evidence within this scan's scope and vantage point. This statement is limited to the data actually collected — it is not a guarantee of security, and observations in §14 still require review.`);
  }
  if (observed.length) {
    R.h2(`Observed items (${observed.length}) — factual observations, not vulnerability claims`);
    R.table([
      { key: 0, label: 'Observation', width: 260 }, { key: 1, label: 'Severity', width: 60 }, { key: 2, label: 'Asset(s)', width: 130 },
    ], observed.map(f => [f.title, f.severity, (f.asset_label || '—').slice(0, 60)]));
  }

  /* ============ 14. MANUAL REVIEW ============ */
  R.pageHeader('Manual Review / Heuristic Items');
  R.h1('14. Manual Review / Heuristic Items');
  const review = findings.filter(f => ['MANUAL_REVIEW', 'HEURISTIC', 'INFERRED'].includes(f.classification));
  if (review.length) {
    R.para(`These items are POTENTIAL issues identified by pattern or classification rules. They are deliberately separated from §13 and must be human-verified before any conclusion or remediation ticket.`);
    review.forEach((f, i) => R.findingBlock(f, i + 1, { compact: true }));
  } else {
    R.para('No manual-review or heuristic items were raised from the collected evidence. This statement reflects only what the executed modules could observe.');
  }

  /* ============ 15. SCAN COMPARISON ============ */
  R.pageHeader('Scan Comparison');
  R.h1('15. Scan Comparison');
  const prev = scan.parent_scan_id ? q1(`SELECT * FROM scans WHERE id = ?`, [scan.parent_scan_id]) : findPreviousScan(scan);
  if (!prev) {
    R.para('No prior completed scan exists for this target — comparison is not applicable for this report.');
  } else {
    const diff = diffScans(prev, scan);
    R.kvTable([
      ['Baseline', `${prev.name} (${(prev.finished_at || prev.created_at || '').replace('T', ' ').slice(0, 16)} UTC)`],
      ['Current', `${scan.name} (${(scan.finished_at || '').replace('T', ' ').slice(0, 16)} UTC)`],
    ]);
    R.h2('Changes');
    const changeRows = [
      ['New assets', diff.assets.added.length], ['Removed assets', diff.assets.removed.length],
      ['New open ports', diff.ports.added.length], ['Ports no longer open', diff.ports.removed.length],
      ['New endpoints', diff.endpoints.added.length], ['Endpoints removed', diff.endpoints.removed.length],
      ['DNS changes', diff.dns.added.length + diff.dns.removed.length],
      ['Certificate changes', diff.certs.added.length + diff.certs.removed.length],
      ['Technology changes', diff.tech.added.length + diff.tech.removed.length],
      ['New findings', diff.findings.added.length], ['Resolved findings', diff.findings.removed.length],
    ];
    R.table([{ key: 0, label: 'Change category', width: 220 }, { key: 1, label: 'Count', width: 70, align: 'right' }], changeRows.map(r => [r[0], String(r[1])]));
    for (const [label, part] of [['New assets (first 20)', diff.assets.added], ['Assets no longer present (first 20)', diff.assets.removed], ['New open ports', diff.ports.added], ['Ports no longer open', diff.ports.removed], ['New endpoints (first 25)', diff.endpoints.added], ['New findings', diff.findings.added], ['Resolved findings', diff.findings.removed]]) {
      if (!part.length) continue;
      R.h2(label);
      R.bullets(part.slice(0, 25));
    }
  }

  /* ============ 16. LIMITATIONS ============ */
  R.pageHeader('Limitations & Coverage Gaps');
  R.h1('16. Limitations & Coverage Gaps');
  const lims = [];
  for (const m of mods) {
    if (m.status === 'FAILED') lims.push(`${m.name} FAILED — ${String(m.error || 'error').slice(0, 160)}. The areas covered by this module could not be assessed.`);
    if (m.status === 'SKIPPED' || m.status === 'NOT_APPLICABLE') {
      let d = {}; try { d = JSON.parse(m.detail || '{}'); } catch {}
      lims.push(`${m.name} ${m.status === 'SKIPPED' ? 'skipped' : 'not applicable'} — ${String(d.reason || 'see module matrix').slice(0, 160)}`);
    }
    if (m.status === 'COMPLETED_NO_RESULTS') {
      let d = {}; try { d = JSON.parse(m.detail || '{}'); } catch {}
      if (d.reason) lims.push(`${m.name} completed with no results — ${String(d.reason).slice(0, 150)}`);
    }
  }
  if (scan.mode !== 'ACTIVE_CONFIRMED') lims.push('Scan ran in PASSIVE-ONLY mode: no port states, live-host status or response-based observations were determined.');
  lims.push('Rate limits and time-boxes cap request volume; low-and-slow evasion of monitoring is not attempted by design.');
  lims.push('Results reflect a point-in-time collection window and a single network vantage point.');
  lims.push('Subdomain dictionary discovery is bounded by the built-in wordlist; CT-based discovery depends on external log search availability.');
  lims.push('Potential secrets are unverified regex matches (redacted); verification requires human review.');
  R.bullets(lims);

  /* ============ 17. EVIDENCE APPENDIX ============ */
  R.pageHeader('Evidence Appendix');
  R.h1('17. Evidence Appendix');
  const evRows = q(`SELECT id, module_key, kind, source, summary, collected_at FROM evidence WHERE scan_id = ? ORDER BY collected_at`, [scanId]);
  R.para(`Every material statement in this report traces to evidence records like those below (IDs are referenced in findings). ${evRows.length} evidence record(s) were collected. Full raw evidence is included in the downloadable evidence package.`);
  R.table([
    { key: 0, label: 'Evidence ID', width: 120 }, { key: 1, label: 'Module', width: 95 },
    { key: 2, label: 'Kind', width: 85 }, { key: 3, label: 'Summary', width: 150 },
  ], evRows.slice(0, 80).map(e => [e.id.replace('ev_', 'EV-'), e.module_key, e.kind, String(e.summary).slice(0, 80)]));
  if (evRows.length > 80) R.para(`…and ${evRows.length - 80} further evidence records (see JSON/evidence-package exports).`, { size: 8.5, color: C.faint });

  /* footers */
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    doc.save();
    const y = doc.page.height - 40;
    if (i > 0) {
      doc.moveTo(48, y - 12).lineTo(doc.page.width - 48, y - 12).strokeColor(C.line).lineWidth(0.5).stroke();
      doc.fontSize(7.5).fillColor(C.faint).text('KavachRecon Intelligence Platform • Built by @premkrs', 48, y - 4, { lineBreak: false });
      doc.text(`Page ${i + 1} of ${range.count}`, doc.page.width - 140, y - 4, { width: 92, align: 'right', lineBreak: false });
    }
    doc.restore();
  }

  doc.end();
}

/* ================= renderer helpers ================= */
class Renderer {
  constructor(doc) { this.doc = doc; this.section = ''; }
  pageHeader(section) {
    const d = this.doc;
    if (d.y > 80) { d.addPage(); }
    this.section = section;
    d.save();
    d.rect(0, 0, d.page.width, 30).fill(C.brand);
    d.fontSize(8).fillColor('#9fb3c8').text(`KAVACHRECON — AUTHORIZED RECONNAISSANCE REPORT`, 48, 11, { characterSpacing: 1 });
    d.fontSize(8).fillColor('#e7eef5').text(section.toUpperCase(), d.page.width - 250, 11, { width: 202, align: 'right' });
    d.restore();
    d.y = 56;
  }
  coverPage({ scan, target, workspace, creator }) {
    const d = this.doc;
    const h = d.page.height;
    d.rect(0, 0, d.page.width, h).fill('#ffffff');
    d.rect(0, 0, d.page.width, 240).fill(C.brand);
    d.rect(0, 240, d.page.width, 4).fill(C.accent);
    // shield mark
    d.save().translate(64, 64).fillColor(C.accent);
    d.moveTo(14, 0).lineTo(0, 6).lineTo(0, 20).quadraticCurveTo(0, 34, 14, 42).quadraticCurveTo(28, 34, 28, 20).lineTo(28, 6).lineTo(14, 0).lineWidth(0).fill();
    d.fillColor('#ffffff').fontSize(9).text('KAVACH', 44, 12, { characterSpacing: 2 });
    d.fillColor(C.accent).fontSize(9).text('RECON', 44, 12, { characterSpacing: 2 }).moveUp();
    d.restore();
    d.fontSize(26).fillColor('#ffffff').font('Helvetica-Bold').text('KavachRecon', 64, 120);
    d.fontSize(12).fillColor('#bcd0e2').font('Helvetica').text('Attack-Surface Intelligence Platform', 64, 152);
    d.fontSize(10).fillColor('#8fa8bf').text('Authorized reconnaissance • Evidence-based • Deterministic risk', 64, 172);

    d.font('Helvetica-Bold').fontSize(20).fillColor(C.ink).text(scan.name, 64, 300, { width: d.page.width - 128 });
    d.moveDown(0.4);
    d.font('Helvetica').fontSize(11).fillColor(C.sub).text(`Target: ${target.identifier} (${target.type})`, 64);
    d.text(`Workspace: ${workspace.name}`);
    d.moveDown(0.8);
    const rows = [
      ['Scan mode', scan.mode === 'ACTIVE_CONFIRMED' ? 'ACTIVE — operator confirmed' : 'PASSIVE-ONLY'],
      ['Scan started', (scan.started_at || '—').replace('T', ' ').slice(0, 19) + ' UTC'],
      ['Scan completed', (scan.finished_at || '—').replace('T', ' ').slice(0, 19) + ' UTC'],
      ['Scan ID', scan.id],
      ['Prepared by', '@premkrs — KavachRecon Intelligence Platform'],
    ];
    let y = d.y + 10;
    for (const [k, v] of rows) {
      d.rect(64, y, d.page.width - 128, 26).fill(C.bg);
      d.fontSize(9).fillColor(C.faint).text(k.toUpperCase(), 76, y + 9, { characterSpacing: 0.5 });
      d.fontSize(10).fillColor(C.ink).text(v, 260, y + 9, { width: d.page.width - 340 });
      y += 30;
    }
    d.y = y + 20;
    d.fontSize(9).fillColor(C.faint).text('CONFIDENTIAL — intended for authorized recipients only. All reconnaissance was performed against the explicitly authorized target under the operator-confirmed scope recorded in §2. Evidence references throughout this report point to data actually collected during the scan.', 64, h - 180, { width: d.page.width - 128, lineGap: 3 });
    d.fontSize(8.5).fillColor(C.accentDark).text('KavachRecon Intelligence Platform • Built by @premkrs', 64, h - 80);
  }
  spacer(n = 8) { this.doc.y += n; }
  h1(text) {
    const d = this.doc;
    d.moveDown(0.3);
    d.fontSize(17).font('Helvetica-Bold').fillColor(C.brand).text(text, { paragraphGap: 4 });
    d.moveTo(48, d.y).lineTo(d.page.width - 48, d.y).lineWidth(2).strokeColor(C.accent).stroke();
    d.moveDown(0.6);
  }
  h2(text, { size = 12.5 } = {}) {
    const d = this.doc;
    this.ensure(48);
    d.moveDown(0.5);
    d.fontSize(size).font('Helvetica-Bold').fillColor(C.brand2).text(text, { paragraphGap: 3 });
    d.moveDown(0.2);
  }
  para(text, { size = 9.5, color = C.ink } = {}) {
    this.ensure(40);
    this.doc.fontSize(size).font('Helvetica').fillColor(color).text(text, { lineGap: 2.5, paragraphGap: 5 });
  }
  meta(text) { this.doc.fontSize(8.5).font('Helvetica').fillColor(C.faint).text(text, { paragraphGap: 8 }); }
  bullets(items, { size = 9 } = {}) {
    const d = this.doc;
    for (const it of items) {
      this.ensure(30);
      d.fontSize(size).font('Helvetica').fillColor(C.ink);
      const bullet = '•  ' + String(it);
      d.text(bullet, 54, d.y, { width: d.page.width - 106, lineGap: 2 });
      d.x = 48;
    }
    d.moveDown(0.4);
  }
  list(items) {
    const d = this.doc;
    d.fontSize(10).font('Helvetica').fillColor(C.ink);
    d.list(items, { lineGap: 3 });
  }
  code(text) {
    const d = this.doc;
    this.ensure(80);
    d.save();
    const h = Math.min(d.heightOfString(text, { font: 'Courier', fontSize: 7.5, lineGap: 1 }), 320);
    d.rect(48, d.y, d.page.width - 96, h + 10).fill('#0d1520');
    d.fillColor('#9fe8dd').font('Courier').fontSize(7.5).text(text, 56, d.y + 5, { width: d.page.width - 112, lineGap: 1 });
    d.restore();
    d.y += h + 18; d.x = 48;
  }
  ensure(h) { if (this.doc.y + h > this.doc.page.height - 80) this.doc.addPage(); }
  callout(title, text, kind = 'info') {
    const d = this.doc;
    this.ensure(90);
    const y = d.y;
    const color = kind === 'warn' ? C.med : C.brand2;
    d.save();
    const h = d.heightOfString(text, { fontSize: 9, width: d.page.width - 130, lineGap: 2 }) + 34;
    d.rect(48, y, d.page.width - 96, h).fill(kind === 'warn' ? '#fdf6ec' : C.bg);
    d.rect(48, y, 3, h).fill(color);
    d.fontSize(9.5).font('Helvetica-Bold').fillColor(color).text(title, 62, y + 8);
    d.fontSize(9).font('Helvetica').fillColor(C.ink).text(text, 62, y + 24, { width: d.page.width - 130, lineGap: 2 });
    d.restore();
    d.y = y + h + 12;
  }
  statGrid(stats) {
    const d = this.doc;
    const cols = 3, w = (d.page.width - 96 - 12 * (cols - 1)) / cols, ch = 44;
    let x = 48, y = d.y + 4;
    for (let i = 0; i < stats.length; i++) {
      const [label, value] = stats[i];
      const cx = 48 + (i % cols) * (w + 12), cy = y + Math.floor(i / cols) * (ch + 8);
      this.ensure(ch + 8);
      if (cy !== y + Math.floor((i - (i % cols === 0 && i !== 0 ? cols : 0)) / cols) * (ch + 8)) { y = d.y + 4; }
      d.rect(cx, cy, w, ch).fill(C.bg).lineWidth(0.75).strokeColor(C.line).stroke();
      d.fontSize(15).font('Helvetica-Bold').fillColor(C.brand).text(String(value), cx + 10, cy + 7);
      d.fontSize(7).font('Helvetica').fillColor(C.sub).text(label.toUpperCase(), cx + 10, cy + 27, { characterSpacing: 0.6 });
      if (i % cols === cols - 1 || i === stats.length - 1) d.y = cy + ch + 8;
    }
    d.x = 48;
    d.y = y + Math.ceil(stats.length / cols) * (ch + 8) + 8;
  }
  table(cols, rows, { sevColor, statusColor, stateColor } = {}) {
    const d = this.doc;
    const widths = cols.map(c => c.width);
    const total = widths.reduce((a, b) => a + b, 0);
    const scale = (d.page.width - 96) / total;
    const W = widths.map(w => w * scale);
    const fontSize = 8.2, pad = 4;
    const rowH = (cells) => {
      let maxH = 14;
      cells.forEach((c, i) => {
        const h = d.heightOfString(String(c ?? '—'), { width: W[i] - pad * 2, fontSize, lineGap: 1 });
        if (h + pad * 2 > maxH) maxH = h + pad * 2;
      });
      return maxH;
    };
    // header
    this.ensure(60);
    let x = 48, y = d.y;
    d.save();
    d.rect(48, y, d.page.width - 96, 20).fill(C.headFill);
    cols.forEach((c, i) => {
      d.fontSize(7.5).font('Helvetica-Bold').fillColor('#cfe0ee').text(c.label.toUpperCase(), x + pad, y + 7, { width: W[i] - pad * 2, align: c.align || 'left', characterSpacing: 0.5 });
      x += W[i];
    });
    y += 20;
    rows.forEach((r, ri) => {
      const h = rowH(r);
      if (y + h > d.page.height - 90) { d.addPage(); this.pageHeaderKeep(); x = 48; y = d.y; d.rect(48, y, d.page.width - 96, 20).fill(C.headFill); x = 48; cols.forEach((c, i) => { d.fontSize(7.5).font('Helvetica-Bold').fillColor('#cfe0ee').text(c.label.toUpperCase(), x + pad, y + 7, { width: W[i] - pad * 2, align: c.align || 'left' }); x += W[i]; }); y += 20; }
      if (ri % 2 === 1) { d.rect(48, y, d.page.width - 96, h).fill(C.rowAlt); }
      x = 48;
      cols.forEach((c, i) => {
        const val = String(r[c.key] ?? '—');
        let color = C.ink;
        if (sevColor && i === 0) color = sevColor(val) || C.ink;
        if (statusColor && i === 1) color = statusColor(val) || C.ink;
        if (stateColor && i === 1) color = stateColor(val) || C.ink;
        d.fontSize(fontSize).font('Helvetica').fillColor(color).text(val, x + pad, y + pad, { width: W[i] - pad * 2, align: c.align || 'left', lineGap: 1 });
        x += W[i];
      });
      d.moveTo(48, y + h).lineTo(d.page.width - 48, y + h).lineWidth(0.4).strokeColor(C.line).stroke();
      y += h;
    });
    d.restore();
    d.y = y + 10; d.x = 48;
  }
  pageHeaderKeep() { const d = this.doc; d.rect(0, 0, d.page.width, 30).fill(C.brand); d.fontSize(8).fillColor('#e7eef5').text(this.section.toUpperCase(), d.page.width - 250, 11, { width: 202, align: 'right' }); d.y = 52; }
  kvTable(pairs) {
    const d = this.doc;
    for (const [k, v] of pairs) {
      this.ensure(24);
      const h = Math.max(d.heightOfString(String(v), { width: d.page.width - 96 - 150, fontSize: 9, lineGap: 1.5 }), 15) + 8;
      d.rect(48, d.y, d.page.width - 96, h).fill(d.y % 2 ? C.bg : '#ffffff');
      d.fontSize(8).font('Helvetica-Bold').fillColor(C.sub).text(k.toUpperCase(), 56, d.y + 5, { width: 145 });
      d.fontSize(9).font('Helvetica').fillColor(C.ink).text(String(v), 210, d.y + 5, { width: d.page.width - 96 - 170, lineGap: 1.5 });
      d.y += h + 2;
    }
    d.moveDown(0.5);
  }
  findingBlock(f, idx, { compact = false } = {}) {
    const d = this.doc;
    this.ensure(120);
    const y0 = d.y;
    const color = SEV_COLOR[f.severity] || C.info;
    const headH = 22;
    d.rect(48, y0, d.page.width - 96, headH).fill(color);
    d.fontSize(9).font('Helvetica-Bold').fillColor('#ffffff').text(`${idx}.  [${f.classification}]  ${f.severity}  •  risk ${f.risk_score}/100  •  confidence ${f.confidence}`, 56, y0 + 6);
    d.y = y0 + headH + 6;
    d.fontSize(10).font('Helvetica-Bold').fillColor(C.ink).text(f.title, { paragraphGap: 3 });
    d.fontSize(8).font('Helvetica').fillColor(C.faint).text(`ID ${f.finding_key || f.id}  •  category ${f.category}  •  asset: ${f.asset_label || '—'}  •  evidence: ${(JSON.parse(f.evidence_ids || '[]')).map(e => 'EV-' + String(e).replace('ev_', '')).join(', ') || '—'}`, { paragraphGap: 4 });
    d.fontSize(9).font('Helvetica').fillColor(C.ink).text(f.description, { paragraphGap: 3, lineGap: 1.5 });
    if (!compact) {
      if (f.impact) d.fontSize(9).font('Helvetica-Bold').fillColor(C.brand2).text('Impact: ', { continued: true }).font('Helvetica').fillColor(C.ink).text(f.impact, { paragraphGap: 3 });
      if (f.recommendation) d.fontSize(9).font('Helvetica-Bold').fillColor(C.accentDark).text('Recommended action: ', { continued: true }).font('Helvetica').fillColor(C.ink).text(f.recommendation, { paragraphGap: 3 });
    }
    d.moveDown(0.6);
  }
}

function moduleStatusColor(v) {
  return { COMPLETED: C.ok, COMPLETED_NO_RESULTS: C.sub, FAILED: C.high, SKIPPED: C.faint, NOT_APPLICABLE: C.faint, QUEUED: C.faint, RUNNING: C.med }[v] || C.ink;
}
function postureColor(v) {
  if (['EXPIRED', 'WEAK_PROTOCOL', 'WEAK_FLAGS', 'NOT_ENFORCED'].includes(v)) return C.high;
  if (['EXPIRING_SOON', 'MISSING'].includes(v)) return C.med;
  if (['PRESENT', 'ENFORCED', 'VALID', 'SECURE_FLAGS', 'OK'].includes(v)) return C.ok;
  return C.ink;
}
function tlsBrief(tlsJson) {
  try {
    const t = JSON.parse(tlsJson);
    if (!t.ok) return `handshake failed (${t.error || 'unknown'})`;
    const cert = t.cert || {};
    return `${t.protocol}, ${t.cipher || '?'}; cert CN=${cert.subject?.CN || 'n/a'} (${cert.issuer?.O || cert.issuer?.CN || 'issuer n/a'}), valid to ${cert.valid_to || 'n/a'}`;
  } catch { return '—'; }
}
function headerBrief(headers) {
  const keys = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
  return keys.map(k => `${k}=${headers[k] ? 'set' : 'absent'}`).join(' · ');
}
function sanitize(s) { return String(s).replace(/[^\w.-]+/g, '_').slice(0, 40) || 'scan'; }

export function findPreviousScan(scan) {
  return q1(`SELECT * FROM scans WHERE target_id = ? AND id != ? AND status IN ('COMPLETED','COMPLETED_WITH_FAILURES') AND created_at < ? ORDER BY created_at DESC LIMIT 1`, [scan.target_id, scan.id, scan.created_at]);
}

export function diffScans(prev, cur) {
  const set = (rows, keyFn) => new Set(rows.map(keyFn));
  const diffSets = (a, b, fmt = (x) => x) => {
    const added = [...b].filter(x => !a.has(x));
    const removed = [...a].filter(x => !b.has(x));
    return { added: added.map(fmt), removed: removed.map(fmt) };
  };
  const portsOf = (sid) => q(`SELECT host, ip, port, service, state FROM host_ports WHERE scan_id = ? AND state = 'OPEN'`, [sid]).map(p => `${p.host}:${p.port} (${p.service || '?'})`);
  const epsOf = (sid) => q(`SELECT url FROM endpoints WHERE scan_id = ?`, [sid]).map(e => e.url);
  const dnsOf = (sid) => q(`SELECT type, name, value FROM dns_records WHERE scan_id = ?`, [sid]).map(d => `${d.type} ${d.name} → ${String(d.value).slice(0, 60)}`);
  const certsOf = (sid) => q(`SELECT url, value FROM posture WHERE scan_id = ? AND kind = 'CERT'`, [sid]).map(c => `${c.url}: ${c.value}`);
  const techOf = (sid) => q(`SELECT name, version FROM technologies WHERE scan_id = ?`, [sid]).map(t => t.version ? `${t.name} ${t.version}` : t.name);
  const findOf = (sid) => q(`SELECT finding_key, title, severity FROM findings WHERE scan_id = ?`, [sid]).map(f => `[${f.severity}] ${f.title}`);
  const assetsOf = (wid, sid) => q(`SELECT DISTINCT a.type, a.key FROM assets a JOIN evidence e ON e.asset_id = a.id AND e.scan_id = ? WHERE a.workspace_id = ?`, [sid, wid]).map(a => `${a.type.toLowerCase()}:${a.key}`);
  return {
    assets: diffSets(assetsOf(prev.workspace_id, prev.id), assetsOf(cur.workspace_id, cur.id)),
    ports: diffSets(new Set(portsOf(prev.id)), new Set(portsOf(cur.id))),
    endpoints: diffSets(new Set(epsOf(prev.id)), new Set(epsOf(cur.id))),
    dns: diffSets(new Set(dnsOf(prev.id)), new Set(dnsOf(cur.id))),
    certs: diffSets(new Set(certsOf(prev.id)), new Set(certsOf(cur.id))),
    tech: diffSets(new Set(techOf(prev.id)), new Set(techOf(cur.id))),
    findings: diffSets(new Set(findOf(prev.id)), new Set(findOf(cur.id))),
  };
}
