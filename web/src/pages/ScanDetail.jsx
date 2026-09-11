import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api, ago, fmtDT } from '../lib/api.js';
import { useApp } from '../App.jsx';
import { ModStatus, ScanStatus, ModeBadge, DemoBadge, SevBadge, ClassBadge, Empty, Loading, useToast, Markdown, Modal, Confirm, usePoll } from '../lib/ui.jsx';

const TABS = [
  ['overview', 'Overview'], ['dns', 'DNS'], ['network', 'Network'], ['web', 'Web'], ['endpoints', 'Endpoints'],
  ['js', 'JavaScript'], ['tech', 'Tech & Perimeter'], ['posture', 'Posture'], ['findings', 'Findings'],
  ['compare', 'Compare'], ['ai', 'AI'], ['evidence', 'Evidence'], ['export', 'Export'],
];

export default function ScanDetail() {
  const { id } = useParams();
  const { wsId } = useApp();
  const toast = useToast();
  const [scan, setScan] = useState(null);
  const [tab, setTab] = useState('overview');
  const [notFound, setNotFound] = useState(false);

  const load = useCallback(async () => {
    try { setScan(await api.get(`/scans/${id}`)); } catch (e) { if (e.status === 404) setNotFound(true); }
  }, [id]);
  useEffect(() => { load(); }, [load]);
  usePoll(load, 3000, !!scan && ['QUEUED', 'RUNNING'].includes(scan?.status));

  if (notFound) return <Empty icon="🕳️" title="Scan not found" hint="It may have been deleted." action={<Link className="btn" to="/scans">Back to scans</Link>} />;
  if (!scan) return <Loading label="Loading scan…" />;

  const running = ['QUEUED', 'RUNNING'].includes(scan.status);

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="card">
        <div className="row wrap">
          <div className="grow" style={{ minWidth: 220 }}>
            <div className="row wrap" style={{ gap: 8 }}>
              <span style={{ fontWeight: 800, fontSize: 17 }}>{scan.name}</span>
              <ScanStatus s={scan.status} />
              <ModeBadge m={scan.mode} />
              <DemoBadge demo={scan.is_demo} />
            </div>
            <div className="muted small" style={{ marginTop: 4 }}>
              Target <b className="mono">{scan.target_identifier}</b> ({scan.target_type}) · workspace {scan.workspace_name} ·
              started {fmtDT(scan.started_at)} · {scan.finished_at ? `finished ${fmtDT(scan.finished_at)}` : running ? 'in progress…' : 'no finish time'}
            </div>
          </div>
          <button className="btn" onClick={async () => { try { const s = await api.post(`/scans/${id}/rerun`); toast('Rerun launched'); location.assign(`/scans/${s.id}`); } catch (e) { toast(e.message, 'err'); } }}>↻ Rerun</button>
        </div>
        {running && <div style={{ marginTop: 10 }}><progress value={scan.modules.filter(m => !['QUEUED'].includes(m.status)).length} max={scan.modules.length} /></div>}
      </div>

      <div className="tabs">{TABS.map(([k, label]) => <button key={k} className={`tab ${tab === k ? 'active' : ''}`} onClick={() => setTab(k)}>{label}</button>)}</div>

      {tab === 'overview' && <Overview scan={scan} />}
      {tab === 'dns' && <DnsTab id={id} />}
      {tab === 'network' && <NetworkTab id={id} />}
      {tab === 'web' && <WebTab id={id} />}
      {tab === 'endpoints' && <EndpointsTab id={id} />}
      {tab === 'js' && <JsTab id={id} />}
      {tab === 'tech' && <TechTab id={id} />}
      {tab === 'posture' && <PostureTab id={id} />}
      {tab === 'findings' && <FindingsTab id={id} />}
      {tab === 'compare' && <CompareTab scan={scan} />}
      {tab === 'ai' && <AiTab scan={scan} />}
      {tab === 'evidence' && <EvidenceTab id={id} />}
      {tab === 'export' && <ExportTab scan={scan} />}
    </div>
  );
}

/* ================= Overview ================= */
function Overview({ scan }) {
  const summary = scan.summary || {};
  const t = summary.totals || {};
  const statusOrder = ['RUNNING', 'FAILED', 'SKIPPED', 'NOT_APPLICABLE', 'COMPLETED_NO_RESULTS', 'COMPLETED', 'QUEUED'];
  const mods = [...scan.modules].sort((a, b) => statusOrder.indexOf(a.status) - statusOrder.indexOf(b.status) || a.order_idx - b.order_idx);
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {summary.failed_modules > 0 && (
        <div className="callout danger"><b>{summary.failed_modules} module(s) failed.</b> The areas they cover could NOT be assessed — this scan must not be read as “no findings” for those areas. See the matrix below.</div>
      )}
      <div className="grid g4">
        {[['Assets touched', t.scan_assets], ['DNS records', t.dns_records], ['Open ports', t.open_ports], ['Live hosts', t.live_hosts],
          ['Web responses', t.web_apps], ['Endpoints', t.endpoints], ['Technologies', t.technologies], ['Evidence records', t.evidence]].map(([l, v]) => (
          <div key={l} className="stat"><div className="v">{v ?? 0}</div><div className="l">{l}</div></div>
        ))}
      </div>
      <div className="card pad0">
        <div className="row" style={{ padding: '13px 16px', borderBottom: '1px solid var(--line)' }}>
          <h3 style={{ margin: 0 }}>Module execution matrix</h3>
          <div className="spacer" />
          <span className="muted small">FAILED ≠ “no vulnerabilities”. SKIPPED/N-A = not run, with reason.</span>
        </div>
        <div className="tblwrap"><table className="tbl">
          <thead><tr><th>#</th><th>Module</th><th>Status</th><th>Items</th><th>Time</th><th>Detail / error</th></tr></thead>
          <tbody>
            {mods.map((m, i) => {
              let detail = null; try { detail = JSON.parse(m.detail || '{}'); } catch { }
              return (
                <tr key={m.id}>
                  <td className="muted">{i + 1}</td>
                  <td style={{ fontWeight: 600 }}>{m.name}<div className="muted small mono">{m.module_key}</div></td>
                  <td><ModStatus s={m.status} /></td>
                  <td style={{ fontWeight: 700 }}>{m.items_count}</td>
                  <td className="dim">{m.duration_ms ? `${(m.duration_ms / 1000).toFixed(1)}s` : '—'}</td>
                  <td className="dim small" style={{ maxWidth: 340 }}>
                    {m.status === 'FAILED' ? <span style={{ color: 'var(--red)' }}>{m.error}</span>
                      : detail?.reason ? detail.reason
                        : detail?.note ? detail.note : '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table></div>
      </div>
    </div>
  );
}

/* ================= data-tab helper ================= */
function useTabData(id, kind) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => { setData(null); api.get(`/scans/${id}/data/${kind}`).then(setData).catch(e => setErr(e.message)); }, [id, kind]);
  return { data, err };
}
const NoData = ({ modKey, reason }) => (
  <Empty icon="∅" title="No records in this scan" hint={reason || 'The module that produces this data did not yield records. Check the Overview matrix — a FAILED or NOT_APPLICABLE module means this area was NOT assessed (which is not evidence of absence).'} />
);

/* ================= DNS ================= */
function DnsTab({ id }) {
  const { data } = useTabData(id, 'dns');
  if (!data) return <Loading />;
  if (data.length === 0) return <NoData />;
  const byType = {};
  data.forEach(r => (byType[r.type] = byType[r.type] || []).push(r));
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {Object.entries(byType).map(([type, rows]) => (
        <div key={type} className="card pad0">
          <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)' }}>
            <span className="badge b-purple">{type}</span><span className="muted small">{rows.length} record{rows.length > 1 ? 's' : ''}</span>
          </div>
          <div className="tblwrap"><table className="tbl">
            <thead><tr><th>Name</th><th>Value</th><th>Collected</th></tr></thead>
            <tbody>{rows.slice(0, 40).map(r => (
              <tr key={r.id}><td className="mono dim">{r.name}</td><td className="mono prewrap">{String(r.value)}</td><td className="dim small">{ago(r.collected_at)}</td></tr>
            ))}</tbody>
          </table></div>
        </div>
      ))}
    </div>
  );
}

/* ================= Network ================= */
function NetworkTab({ id }) {
  const { data } = useTabData(id, 'network');
  if (!data) return <Loading />;
  if (data.length === 0) return <NoData reason="No port results. If this scan was PASSIVE-ONLY, port states were not determined by design — run an authorized ACTIVE scan to populate this view." />;
  const open = data.filter(p => ['OPEN', 'OPEN_UNVERIFIED'].includes(p.state));
  const rest = data.filter(p => !['OPEN', 'OPEN_UNVERIFIED'].includes(p.state));
  const StateBadge = ({ s }) => <span className={`badge ${s === 'OPEN' ? 'b-red' : s === 'OPEN_UNVERIFIED' ? 'b-gold' : s === 'CLOSED' ? 'b-gray' : 'b-blue'}`}>{s.replace('_', ' ')}</span>;
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="row wrap" style={{ gap: 6 }}>
        <span className="badge b-red">OPEN × {open.filter(p => p.state === 'OPEN').length}</span>
        <span className="badge b-gold">OPEN_UNVERIFIED × {open.filter(p => p.state === 'OPEN_UNVERIFIED').length}</span>
        <span className="badge b-gray">closed/filtered × {rest.length}</span>
        <span className="muted small">OPEN_UNVERIFIED = TCP accept without confirming response — NOT a confirmed service.</span>
      </div>
      <div className="card pad0 tblwrap"><table className="tbl">
        <thead><tr><th>Host</th><th>IP</th><th>Port</th><th>State</th><th>Service</th><th>Banner / version (as captured)</th><th>Confidence</th></tr></thead>
        <tbody>{[...open, ...rest.slice(0, 50)].map(p => (
          <tr key={p.id}>
            <td className="mono">{p.host}</td><td className="mono dim">{p.ip}</td>
            <td className="mono" style={{ fontWeight: 700 }}>{p.port}/tcp</td>
            <td><StateBadge s={p.state} /></td>
            <td>{p.service || '—'}</td>
            <td className="mono dim small prewrap" style={{ maxWidth: 360 }}>{p.banner ? p.banner.replace(/\s+/g, ' ').slice(0, 160) : (p.version || '—')}</td>
            <td><span className={`badge ${p.confidence === 'HIGH' ? 'b-green' : p.confidence === 'MEDIUM' ? 'b-blue' : 'b-gold'}`}>{p.confidence}</span></td>
          </tr>
        ))}</tbody>
      </table></div>
    </div>
  );
}

/* ================= Web ================= */
function WebTab({ id }) {
  const { data } = useTabData(id, 'web');
  if (!data) return <Loading />;
  const ok = data.filter(w => w.ok);
  if (ok.length === 0) return <NoData reason="No reachable HTTP/HTTPS observations. Probing may have failed due to network egress restrictions — this is a data-collection limitation, NOT evidence that no web applications exist." />;
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {ok.map(w => {
        const headers = JSON.parse(w.headers || '{}');
        const chain = JSON.parse(w.redirect_chain || '[]');
        const tls = w.tls ? JSON.parse(w.tls) : null;
        const secHeaders = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
        return (
          <div key={w.id} className="card">
            <div className="row wrap" style={{ gap: 8, marginBottom: 8 }}>
              <span className={`badge ${w.status_code < 300 ? 'b-green' : w.status_code < 400 ? 'b-blue' : 'b-orange'}`}>HTTP {w.status_code}</span>
              <span className="mono" style={{ fontWeight: 700, wordBreak: 'break-all' }}>{w.url}</span>
              {w.title && <span className="muted small">“{w.title}”</span>}
            </div>
            <div className="kv">
              <div className="k">Final URL</div><div className="mono small prewrap">{w.final_url}</div>
              <div className="k">Redirect chain</div><div className="small">{chain.length ? chain.map((c, i) => <div key={i} className="mono dim">{c.status} → {c.location}</div>) : <span className="muted">none observed</span>}</div>
              <div className="k">Server / Type</div><div className="small mono">{w.server || '(absent)'} · {w.content_type || '(absent)'}</div>
              <div className="k">Security headers</div>
              <div className="row wrap" style={{ gap: 5 }}>
                {secHeaders.map(h => <span key={h} className={`badge ${headers[h] ? 'b-green' : 'b-gray'}`} title={headers[h] || 'absent from this response'}>{h} {headers[h] ? '✓' : '✗'}</span>)}
              </div>
              {tls && (
                <>
                  <div className="k">TLS</div>
                  <div className="small">{tls.ok
                    ? <span className="row wrap" style={{ gap: 5 }}>
                        <span className={`badge ${tls.protocol === 'TLSv1.3' || tls.protocol === 'TLSv1_3' ? 'b-green' : tls.legacySupport?.tls10 || tls.legacySupport?.tls11 ? 'b-red' : 'b-blue'}`}>{String(tls.protocol).replace('_', '.')}</span>
                        <span className="badge b-gray">{tls.cipher}</span>
                        {tls.cert && <span className="badge b-gray">CN {tls.cert.subject?.CN} · {tls.cert.issuer?.O || tls.cert.issuer?.CN} · valid to {String(tls.cert.valid_to).slice(0, 10)}</span>}
                      </span>
                    : <span className="muted">handshake failed — {tls.error}</span>}</div>
                </>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ================= Endpoints ================= */
const EP_CLS = { LOGIN: 'b-blue', AUTHENTICATION: 'b-purple', ADMIN: 'b-orange', API: 'b-teal', UPLOAD: 'b-gold', DOCUMENTATION: 'b-gray', STATIC: 'b-gray', PUBLIC: 'b-gray', POTENTIALLY_SENSITIVE: 'b-red' };
function EndpointsTab({ id }) {
  const { data } = useTabData(id, 'endpoints');
  const [filter, setFilter] = useState('ALL');
  if (!data) return <Loading />;
  if (data.length === 0) return <NoData reason="No endpoints discovered. Endpoint extraction requires reachable pages (HTML links, robots, sitemaps) — if probing failed, coverage is incomplete." />;
  const classes = ['ALL', ...new Set(data.map(e => e.classification))];
  const rows = data.filter(e => filter === 'ALL' || e.classification === filter);
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="row wrap" style={{ gap: 6 }}>
        {classes.map(c => <button key={c} className={`btn sm ${filter === c ? 'primary' : 'ghost'}`} onClick={() => setFilter(c)}>{c.replace(/_/g, ' ').toLowerCase()}</button>)}
      </div>
      <div className="callout">Classifications are pattern-based with evidence — <b>an ADMIN classification is a potential finding, not a vulnerability</b>. Verify manually before concluding (see Findings tab).</div>
      <div className="card pad0 tblwrap"><table className="tbl">
        <thead><tr><th>URL</th><th>Classification</th><th>HTTP</th><th>Note</th></tr></thead>
        <tbody>{rows.map(e => (
          <tr key={e.id}>
            <td className="mono prewrap" style={{ maxWidth: 430, wordBreak: 'break-all' }}>{e.url}</td>
            <td><span className={`badge ${EP_CLS[e.classification] || 'b-gray'}`}>{e.classification.replace(/_/g, ' ')}</span></td>
            <td className="mono">{e.status_code ?? '—'}</td>
            <td className="dim small" style={{ maxWidth: 300 }}>{e.note}</td>
          </tr>
        ))}</tbody>
      </table></div>
    </div>
  );
}

/* ================= JS ================= */
function JsTab({ id }) {
  const { data } = useTabData(id, 'js');
  if (!data) return <Loading />;
  const { resources, secrets, routes } = data;
  if (!resources?.length) return <NoData reason="No JavaScript resources were collected (no reachable pages referenced external scripts). This does not imply absence of JS exposure." />;
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {secrets?.length > 0 && (
        <div className="card pad0">
          <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)' }}>
            <h3 style={{ margin: 0 }}>Potential secrets ({secrets.length})</h3><div className="spacer" />
            <span className="badge b-gold">redacted · unverified until confirmed</span>
          </div>
          <div className="tblwrap"><table className="tbl">
            <thead><tr><th>Type</th><th>Match (redacted)</th><th>Verified</th><th>File</th><th>Context</th></tr></thead>
            <tbody>{secrets.map(s => (
              <tr key={s.id}>
                <td style={{ fontWeight: 700 }}>{s.kind}</td>
                <td className="mono" style={{ color: 'var(--gold)' }}>{s.match_redacted}</td>
                <td>{s.verified ? <span className="badge b-red">VERIFIED</span> : <span className="badge b-gray">UNVERIFIED</span>}</td>
                <td className="mono dim small" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.url}</td>
                <td className="mono dim small prewrap" style={{ maxWidth: 260 }}>{s.context}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </div>
      )}
      <div className="card pad0">
        <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)' }}>
          <h3 style={{ margin: 0 }}>JavaScript resources ({resources.length})</h3><div className="spacer" /><span className="muted small">{routes?.length || 0} route/API references</span>
        </div>
        <div className="tblwrap"><table className="tbl">
          <thead><tr><th>Resource</th><th>Fetched</th><th>Bytes</th><th>sha256</th><th>Routes</th></tr></thead>
          <tbody>{resources.map(r => (
            <tr key={r.id}>
              <td className="mono prewrap" style={{ maxWidth: 380, wordBreak: 'break-all' }}>{r.url}</td>
              <td>{r.fetched_ok ? <span className="badge b-green">yes</span> : <span className="badge b-red">no</span>}</td>
              <td className="dim">{r.bytes?.toLocaleString()}</td>
              <td className="mono dim small">{String(r.sha256).slice(0, 16)}…</td>
              <td className="mono">{r.routes ?? 0}</td>
            </tr>
          ))}</tbody>
        </table></div>
      </div>
      {routes?.length > 0 && (
        <div className="card pad0">
          <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)' }}><h3 style={{ margin: 0 }}>Routes & endpoint references</h3></div>
          <div className="tblwrap"><table className="tbl">
            <thead><tr><th>Route</th><th>Kind</th><th>Found in</th></tr></thead>
            <tbody>{routes.slice(0, 120).map(rt => (
              <tr key={rt.id}>
                <td className="mono">{rt.route}</td>
                <td><span className="badge b-gray">{rt.kind}</span></td>
                <td className="mono dim small" style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis' }}>{rt.url}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </div>
      )}
    </div>
  );
}

/* ================= Tech & Perimeter ================= */
function TechTab({ id }) {
  const tech = useTabData(id, 'tech');
  const perim = useTabData(id, 'perimeter');
  if (!tech.data || !perim.data) return <Loading />;
  const none = tech.data.length === 0 && perim.data.length === 0;
  if (none) return <NoData reason="No technology or perimeter signatures matched collected evidence. If HTTP collection failed, this could not be evaluated — and absence of detection is never proof a WAF/CDN does not exist." />;
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {tech.data.length > 0 && (
        <div className="card pad0">
          <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)' }}><h3 style={{ margin: 0 }}>Technologies ({tech.data.length}) — evidence-backed only</h3></div>
          <div className="tblwrap"><table className="tbl">
            <thead><tr><th>Technology</th><th>Version</th><th>Category</th><th>Detection method</th><th>Evidence match</th><th>Confidence</th></tr></thead>
            <tbody>{tech.data.map(t => (
              <tr key={t.id}>
                <td style={{ fontWeight: 700 }}>{t.name}</td><td className="mono">{t.version || '—'}</td>
                <td><span className="badge b-gray">{t.category}</span></td>
                <td className="small">{t.detection_method}</td>
                <td className="mono dim small prewrap" style={{ maxWidth: 240 }}>{t.raw_match}</td>
                <td><span className={`badge ${t.confidence === 'HIGH' ? 'b-green' : 'b-blue'}`}>{t.confidence}</span></td>
              </tr>
            ))}</tbody>
          </table></div>
        </div>
      )}
      {perim.data.length > 0 && (
        <div className="card pad0">
          <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)' }}><h3 style={{ margin: 0 }}>Perimeter / edge ({perim.data.length})</h3></div>
          <div className="tblwrap"><table className="tbl">
            <thead><tr><th>Kind</th><th>Name</th><th>Detection</th><th>Raw match</th><th>Confidence</th></tr></thead>
            <tbody>{perim.data.map(p => (
              <tr key={p.id}>
                <td><span className={`badge ${p.kind === 'WAF' ? 'b-red' : p.kind === 'CDN' ? 'b-blue' : 'b-purple'}`}>{p.kind}</span></td>
                <td style={{ fontWeight: 700 }}>{p.name}</td>
                <td className="small">{p.detection_method}</td>
                <td className="mono dim small prewrap" style={{ maxWidth: 240 }}>{p.raw_match}</td>
                <td><span className={`badge ${p.confidence === 'HIGH' ? 'b-green' : 'b-blue'}`}>{p.confidence}</span></td>
              </tr>
            ))}</tbody>
          </table></div>
        </div>
      )}
    </div>
  );
}

/* ================= Posture ================= */
function PostureTab({ id }) {
  const { data } = useTabData(id, 'posture');
  if (!data) return <Loading />;
  if (data.length === 0) return <NoData reason="No HTTP responses were available to assess security posture from." />;
  const urls = [...new Set(data.map(p => p.url))];
  const stBadge = (s) => <span className={`badge ${['EXPIRED', 'WEAK_PROTOCOL', 'WEAK_FLAGS', 'NOT_ENFORCED'].includes(s) ? 'b-red' : ['EXPIRING_SOON', 'MISSING'].includes(s) ? 'b-gold' : ['PRESENT', 'ENFORCED', 'VALID', 'SECURE_FLAGS', 'OK'].includes(s) ? 'b-green' : 'b-gray'}`}>{s.replace(/_/g, ' ')}</span>;
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {urls.map(url => (
        <div key={url} className="card pad0">
          <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)' }}>
            <h3 style={{ margin: 0, wordBreak: 'break-all' }} className="mono">{url}</h3>
          </div>
          <div className="tblwrap"><table className="tbl">
            <thead><tr><th>Check</th><th>State</th><th>Observed value (exact)</th></tr></thead>
            <tbody>{data.filter(p => p.url === url).map(p => (
              <tr key={p.id}>
                <td style={{ fontWeight: 700 }}>{p.kind}</td>
                <td>{stBadge(p.state)}</td>
                <td className="mono small prewrap" style={{ maxWidth: 460 }}>{p.kind === 'COOKIE' ? p.header + ' — ' + (p.value || '') : (p.value || p.header || '(absent from response)')}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </div>
      ))}
    </div>
  );
}

/* ================= Findings ================= */
function FindingsTab({ id }) {
  const [data, setData] = useState(null);
  const toast = useToast();
  const load = useCallback(() => api.get(`/findings?scan_id=${id}`).then(r => setData(r)).catch(e => toast(e.message, 'err')), [id]);
  useEffect(() => { load(); }, [load]);
  if (!data) return <Loading />;
  if (data.items.length === 0) return <NoData reason="No findings were derived from this scan's evidence. If modules failed (see Overview), absence of findings must NOT be read as absence of issues — coverage was incomplete." />;
  return <FindingsList resp={data} reload={load} />;
}

export function FindingsList({ resp, reload }) {
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const open = async (f) => { setSel(f); setDetail(await api.get(`/findings/${f.id}`)); };
  const setStatus = async (f, status) => {
    setBusy(true);
    const prev = resp.items;
    // optimistic
    Object.assign(f, { status });
    reload();
    try { await api.patch(`/findings/${f.id}`, { status }); toast(`Finding marked ${status.replace('_', ' ').toLowerCase()}`); }
    catch (e) { toast(e.message, 'err'); prev && reload(); } finally { setBusy(false); setSel(null); }
  };
  return (
    <>
      <div className="card pad0 tblwrap">
        <table className="tbl">
          <thead><tr><th>Title</th><th>Classification</th><th>Severity</th><th>Risk</th><th>Asset</th><th>Status</th></tr></thead>
          <tbody>{resp.items.map(f => (
            <tr key={f.id} className="click" onClick={() => open(f)}>
              <td style={{ fontWeight: 600, maxWidth: 360 }}>{f.title}</td>
              <td><ClassBadge c={f.classification} /></td>
              <td><SevBadge sev={f.severity} /></td>
              <td><RiskPill v={f.risk_score} /></td>
              <td className="mono dim small" style={{ maxWidth: 170, overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.asset_label}</td>
              <td><StatusBadge s={f.status} /></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      {sel && detail && (
        <Modal wide title={<span className="row wrap" style={{ gap: 8 }}><ClassBadge c={detail.classification} /><SevBadge sev={detail.severity} /><span style={{ fontSize: 14.5 }}>{detail.title}</span></span>} onClose={() => setSel(null)}
          footer={<>
            <button className="btn" onClick={async () => {
              const r = await api.post(`/ai/finding/${detail.id}/explain`).catch(e => ({ ok: false, message: e.message }));
              if (r.ok) { setSel(null); location.assign(`/scans/${detail.scan_id}`); }
              else toast(r.message, 'err');
            }}>✨ Explain with AI</button>
            <div className="spacer" />
            <button className="btn ok" disabled={busy || detail.status === 'VERIFIED'} onClick={() => setStatus(detail, 'VERIFIED')}>✓ Verify real</button>
            <button className="btn" disabled={busy || detail.status === 'RISK_ACCEPTED'} onClick={() => setStatus(detail, 'RISK_ACCEPTED')}>Accept risk</button>
            <button className="btn" disabled={busy || detail.status === 'RESOLVED'} onClick={() => setStatus(detail, 'RESOLVED')}>Mark resolved</button>
            <button className="btn danger" disabled={busy || detail.status === 'FALSE_POSITIVE'} onClick={() => setStatus(detail, 'FALSE_POSITIVE')}>False positive</button>
          </>}>
          <div className="kv" style={{ marginBottom: 12 }}>
            <div className="k">Risk</div><div><RiskPill v={detail.risk_score} /> <span className="muted small">deterministic from severity × classification × confidence</span></div>
            <div className="k">Asset</div><div className="mono small">{detail.asset_label || '—'}</div>
            <div className="k">Category</div><div className="small">{detail.category}</div>
            <div className="k">Status</div><div><StatusBadge s={detail.status} /></div>
          </div>
          <div className="callout" style={{ marginBottom: 10 }}>{detail.description}</div>
          {detail.impact && <div style={{ marginBottom: 10 }}><b className="small">Potential impact</b><div className="small" style={{ color: 'var(--sub)' }}>{detail.impact}</div></div>}
          {detail.recommendation && <div style={{ marginBottom: 12 }}><b className="small">Recommended action</b><div className="small" style={{ color: 'var(--sub)' }}>{detail.recommendation}</div></div>}
          <label className="lbl">Evidence ({detail.evidence?.length || 0})</label>
          {detail.evidence?.map(ev => <EvidenceCard key={ev.id} ev={ev} />)}
          {(!detail.evidence || detail.evidence.length === 0) && <div className="muted small">No stored evidence objects — this rule is based on query-level observations recorded in its description (e.g. DNS absence checks).</div>}
        </Modal>
      )}
    </>
  );
}
export const RiskPill = ({ v }) => {
  const color = v >= 70 ? 'var(--red)' : v >= 45 ? 'var(--orange)' : v >= 25 ? 'var(--gold)' : 'var(--blue)';
  return <span className="mono" style={{ fontWeight: 800, color }}><span style={{ fontSize: 15 }}>{v}</span><span className="muted" style={{ fontSize: 10 }}>/100</span></span>;
};
export const StatusBadge = ({ s }) => {
  const map = { OPEN: 'b-blue', VERIFIED: 'b-red', RESOLVED: 'b-green', RISK_ACCEPTED: 'b-gold', FALSE_POSITIVE: 'b-gray' };
  return <span className={`badge ${map[s] || 'b-gray'}`}>{s.replace('_', ' ')}</span>;
};
export const EvidenceCard = ({ ev }) => {
  const [openC, setOpenC] = useState(false);
  let content = null; try { content = JSON.parse(ev.content || '{}'); } catch { }
  return (
    <div className="evidence">
      <div className="meta">
        <span className="mono" style={{ color: 'var(--accent)' }}>{String(ev.id).replace('ev_', 'EV-')}</span>
        <span>{ev.module_key}</span><span>{ev.kind}</span>
        <span className="mono">{String(ev.collected_at).replace('T', ' ').slice(0, 19)} UTC</span>
        <span className="mono" title="SHA-256 content hash — tamper evidence">#{String(ev.hash).slice(0, 12)}…</span>
      </div>
      <div>{ev.summary}</div>
      <div className="small" style={{ color: 'var(--faint)' }}>source: <span className="src">{ev.source}</span></div>
      {content && Object.keys(content).length > 0 && (
        <>
          <button className="btn sm ghost" style={{ marginTop: 6 }} onClick={() => setOpenC(o => !o)}>{openC ? 'Hide raw evidence' : 'Raw evidence (JSON)'}</button>
          {openC && <pre className="prewrap mono" style={{ fontSize: 11, background: '#0a101d', padding: 10, borderRadius: 8, marginTop: 8, maxHeight: 260, overflow: 'auto' }}>{JSON.stringify(content, null, 1).slice(0, 4000)}</pre>}
        </>
      )}
    </div>
  );
};

/* ================= Compare ================= */
function CompareTab({ scan }) {
  const [scans, setScans] = useState(null);
  const [baseline, setBaseline] = useState('');
  const [diff, setDiff] = useState(null);
  const toast = useToast();
  useEffect(() => { api.get(`/scans?workspace_id=${scan.workspace_id}&status=COMPLETED`).then(setScans).catch(() => setScans([])); }, [scan.workspace_id]);
  useEffect(() => {
    if (baseline && baseline !== scan.id) api.get(`/scans/${scan.id}/compare/${baseline}`).then(r => setDiff(r.diff)).catch(e => toast(e.message, 'err'));
    else setDiff(null);
  }, [baseline]);
  if (!scans) return <Loading />;
  const candidates = scans.filter(s => s.id !== scan.id);
  if (candidates.length === 0) return <Empty icon="⇄" title="Nothing to compare yet" hint="Run another scan of this target, then come back — new/removed assets, ports, endpoints, DNS, certificates, technologies and findings will be diffed here and included in the PDF (§15)." />;
  const Section = ({ label, added, removed, fmt }) => {
    const has = (added?.length || 0) + (removed?.length || 0);
    if (!has) return null;
    return (
      <div className="card pad0">
        <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)', gap: 8 }}>
          <h3 style={{ margin: 0 }}>{label}</h3><div className="spacer" />
          <span className="badge b-green">+{added?.length || 0}</span><span className="badge b-red">−{removed?.length || 0}</span>
        </div>
        <div style={{ padding: 12, display: 'grid', gap: 8 }}>
          {(added || []).slice(0, 25).map(x => <div key={'a' + x} className="small mono" style={{ color: 'var(--green)' }}>+ {fmt ? fmt(x) : x}</div>)}
          {(removed || []).slice(0, 25).map(x => <div key={'r' + x} className="small mono" style={{ color: 'var(--red)' }}>− {fmt ? fmt(x) : x}</div>)}
        </div>
      </div>
    );
  };
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="card">
        <label className="lbl">Baseline scan</label>
        <select className="input" value={baseline} onChange={e => setBaseline(e.target.value)}>
          <option value="">— choose a previous scan —</option>
          {candidates.map(s => <option key={s.id} value={s.id}>{s.name} · {fmtDT(s.finished_at || s.created_at)} · {s.status}</option>)}
        </select>
      </div>
      {diff ? (
        <>
          <div className="row wrap" style={{ gap: 8 }}>
            {[['Assets', diff.assets], ['Ports', diff.ports], ['Endpoints', diff.endpoints], ['DNS', diff.dns], ['Certificates', diff.certs], ['Technologies', diff.tech], ['Findings', diff.findings]].map(([l, d]) => (
              <span key={l} className="badge b-gray">{l}: <b style={{ color: 'var(--green)' }}>+{(d.added || []).length}</b> / <b style={{ color: 'var(--red)' }}>−{(d.removed || []).length}</b></span>
            ))}
          </div>
          <Section label="Assets" added={diff.assets.added} removed={diff.assets.removed} />
          <Section label="Ports & services" added={diff.ports.added} removed={diff.ports.removed} />
          <Section label="Endpoints" added={diff.endpoints.added} removed={diff.endpoints.removed} />
          <Section label="DNS records" added={diff.dns.added} removed={diff.dns.removed} />
          <Section label="Certificates" added={diff.certs.added} removed={diff.certs.removed} />
          <Section label="Technologies" added={diff.tech.added} removed={diff.tech.removed} />
          <Section label="Findings (new / resolved)" added={diff.findings.added} removed={diff.findings.removed} />
        </>
      ) : <div className="callout">Pick a baseline above. Diffs cover assets, ports, endpoints, DNS, certificates, technologies and findings — and flow into the PDF report §15.</div>}
    </div>
  );
}

/* ================= AI ================= */
export function AiTab({ scan }) {
  const toast = useToast();
  const [outputs, setOutputs] = useState(null);
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(null);
  const [openOutput, setOpenOutput] = useState(null);
  const load = useCallback(() => api.get(`/ai/outputs?scan_id=${scan.id}`).then(setOutputs).catch(() => setOutputs([])), [scan.id]);
  useEffect(() => { load(); }, [load]);
  const run = async (kind) => {
    setBusy(kind);
    try {
      const r = kind === 'ask'
        ? await api.post(`/ai/scan/${scan.id}/ask`, { question })
        : await api.post(`/ai/scan/${scan.id}/summary`);
      if (!r.ok) { toast(r.message, 'err'); }
      else { toast('AI output generated (grounded on scan DB)'); setQuestion(''); load(); }
    } catch (e) { toast(e.message, 'err'); } finally { setBusy(null); }
  };
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="callout">
        <b>Grounding policy:</b> the AI receives ONLY this scan's database records and is instructed: <b>no evidence = no claim</b>. Every output below is stored with its grounding context and never invents assets or findings.
      </div>
      <div className="card">
        <div className="row wrap">
          <button className="btn primary" disabled={busy} onClick={() => run('summary')}>{busy === 'summary' ? <span className="spinner" /> : '✨'} Generate executive summary</button>
        </div>
        <div className="row" style={{ marginTop: 10 }}>
          <input className="input" placeholder='Ask about this scan — e.g. "which hosts expose admin-like endpoints?"' value={question}
            onChange={e => setQuestion(e.target.value)} onKeyDown={e => e.key === 'Enter' && question.trim() && run('ask')} />
          <button className="btn" disabled={!question.trim() || !!busy} onClick={() => run('ask')}>{busy === 'ask' ? <span className="spinner" /> : 'Ask'}</button>
        </div>
      </div>
      {!outputs ? <Loading /> : outputs.length === 0 ? (
        <Empty icon="✨" title="No AI outputs yet" hint="Generate an executive summary or ask a question. If no Gemini key is configured (or the endpoint is unreachable from this environment), you'll get an honest error — never a fabricated answer." />
      ) : outputs.map(o => (
        <div key={o.id} className="card">
          <div className="row wrap" style={{ gap: 8 }}>
            <span className={`badge ${o.status === 'OK' ? 'b-teal' : 'b-red'}`}>{o.kind.replace(/_/g, ' ')}</span>
            <span className="muted small mono">{o.model}</span>
            <span className="muted small">{ago(o.created_at)}</span>
            <div className="spacer" />
            {o.status === 'OK' && <button className="btn sm" onClick={() => setOpenOutput(o)}>View</button>}
          </div>
          <div className="small" style={{ color: o.status === 'OK' ? 'var(--sub)' : 'var(--red)', marginTop: 6 }}>
            {o.status === 'OK' ? o.prompt_summary : o.error}
          </div>
        </div>
      ))}
      {openOutput && <AiOutputModal id={openOutput.id} onClose={() => setOpenOutput(null)} />}
    </div>
  );
}
function AiOutputModal({ id, onClose }) {
  const [out, setOut] = useState(null);
  useEffect(() => { api.get(`/ai/outputs/${id}`).then(setOut); }, [id]);
  if (!out) return <Loading />;
  return (
    <Modal wide title={<span>AI {out.kind.replace(/_/g, ' ').toLowerCase()} <span className="muted small mono">· {out.model} · grounded on {Object.keys(JSON.parse(out.grounded_on || '{}')).length} context keys</span></span>} onClose={onClose}>
      <Markdown text={out.content} />
      <div className="callout" style={{ marginTop: 12, fontSize: 12 }}>AI-generated analysis of collected scan data. Statements should be read as derived from the evidence context provided; classification labels in the text (OBSERVED/VERIFIED/INFERRED/…) indicate epistemic status.</div>
    </Modal>
  );
}

/* ================= Evidence ================= */
function EvidenceTab({ id }) {
  const { data } = useTabData(id, 'evidence');
  const [filter, setFilter] = useState('');
  if (!data) return <Loading />;
  if (data.length === 0) return <NoData />;
  const kinds = [...new Set(data.map(e => e.kind))].sort();
  const rows = data.filter(e => !filter || e.kind === filter);
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="row wrap" style={{ gap: 6 }}>
        <button className={`btn sm ${!filter ? 'primary' : 'ghost'}`} onClick={() => setFilter('')}>all ({data.length})</button>
        {kinds.map(k => <button key={k} className={`btn sm ${filter === k ? 'primary' : 'ghost'}`} onClick={() => setFilter(k)}>{k.toLowerCase()} ({data.filter(e => e.kind === k).length})</button>)}
      </div>
      {rows.slice(0, 120).map(ev => <EvidenceCard key={ev.id} ev={ev} />)}
      {rows.length > 120 && <div className="muted small">…{rows.length - 120} more — full package in Export → Evidence ZIP.</div>}
    </div>
  );
}

/* ================= Export ================= */
function ExportTab({ scan }) {
  const toast = useToast();
  const items = [
    ['📄', 'Professional PDF report', 'All 19 report sections — cover, summary, scope, methodology, module matrix, inventories, findings, limitations, evidence appendix.', `/scans/${scan.id}/export/pdf`],
    ['📊', 'Asset inventory (CSV)', 'Every asset observed in this scan with type, status, confidence, first/last seen.', `/scans/${scan.id}/export/assets.csv`],
    ['⚠️', 'Findings (CSV)', 'All findings with classification, severity, deterministic risk, evidence references.', `/scans/${scan.id}/export/findings.csv`],
    ['🧾', 'Full scan data (JSON)', 'Complete machine-readable scan export: modules, evidence, DNS, ports, web, endpoints, JS, technologies, posture, findings.', `/scans/${scan.id}/export/json`],
    ['🔒', 'Evidence package (ZIP)', 'Evidence records with SHA-256 content hashes for tamper-evidence, plus all structured collections.', `/scans/${scan.id}/export/evidence.zip`],
  ];
  const ready = ['COMPLETED', 'COMPLETED_WITH_FAILURES', 'CANCELLED', 'FAILED'].includes(scan.status);
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {!ready && <div className="callout warn">Scan still running — exports become available when it finishes or is cancelled.</div>}
      {items.map(([icon, title, hint, path]) => (
        <div key={title} className="card row wrap">
          <div style={{ fontSize: 22 }}>{icon}</div>
          <div className="grow" style={{ minWidth: 220 }}>
            <div style={{ fontWeight: 700 }}>{title}</div>
            <div className="muted small">{hint}</div>
          </div>
          <button className="btn primary" disabled={!ready} onClick={() => { api.download(path); }}>Download</button>
        </div>
      ))}
      <div className="callout">Exports are generated from the same database rows the dashboard reads — numbers always match. The PDF contains only actual collected data and explicitly lists failed modules and coverage gaps.</div>
    </div>
  );
}
