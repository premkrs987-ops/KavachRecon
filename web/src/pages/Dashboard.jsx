import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, ago, fmtDT } from '../lib/api.js';
import { useApp } from '../App.jsx';
import { Donut, SEV_COLORS, SevBadge, SevBars, ScanStatus, ModStatus, DemoBadge, Empty, Skeleton, usePoll } from '../lib/ui.jsx';

function Stat({ v, l, hl, accent }) {
  return <div className={`stat ${hl ? 'hl' : ''}`}><div className="v" style={accent ? { color: accent } : null}>{v ?? '—'}</div><div className="l">{l}</div></div>;
}

export default function Dashboard() {
  const { wsId, workspaces } = useApp();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!wsId) return;
    try { setData(await api.get(`/dashboard?workspace_id=${wsId}`)); } catch { /* toast-free poll */ } finally { setLoading(false); }
  }, [wsId]);
  useEffect(() => { setLoading(true); load(); }, [load]);
  usePoll(load, 4000, !!wsId);

  if (loading && !data) return <div className="grid g4">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} h={72} />)}</div>;
  if (!data) return <Empty title="No workspace selected" hint="Create or select a workspace to see intelligence." />;
  const t = data.totals;
  const openScans = data.latest_scans.filter(s => ['QUEUED', 'RUNNING'].includes(s.status)).length;
  const demo = workspaces.find(w => w.id === wsId)?.is_demo === 1;

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      {demo && (
        <div className="demo-banner">
          <b>Demo workspace.</b> This dataset is a clearly-labelled demonstration (origin DEMO_SEED) so you can explore the platform. Run a real scan from Targets to collect live data, or purge demo data in Settings.
        </div>
      )}
      {openScans > 0 && (
        <div className="callout"><span className="spinner" style={{ marginRight: 8 }} />{openScans} scan{openScans > 1 ? 's' : ''} in progress — dashboard numbers refresh automatically.</div>
      )}

      <div className="grid g4">
        <Stat v={t.assets} l="Total assets" hl />
        <Stat v={t.live_hosts} l="Live hosts" />
        <Stat v={t.subdomains} l="Subdomains" />
        <Stat v={t.domains} l="Domains" />
        <Stat v={t.ips} l="IP addresses" />
        <Stat v={t.open_ports} l="Open ports" />
        <Stat v={t.services} l="Distinct services" />
        <Stat v={t.web_apps} l="Web responses" />
      </div>
      <div className="grid g4">
        <Stat v={t.endpoints} l="Endpoints" />
        <Stat v={t.technologies} l="Technologies" />
        <Stat v={t.dns_records} l="DNS records" />
        <Stat v={t.js_secrets} l="JS secret patterns" accent={t.js_secrets ? 'var(--gold)' : null} />
      </div>

      <div className="grid" style={{ gridTemplateColumns: '1.35fr 1fr', }}>
        <div className="card">
          <div className="row" style={{ marginBottom: 8 }}>
            <h3 style={{ margin: 0 }}>Risk distribution</h3><div className="spacer" />
            <span className="badge b-gray">{t.findings} open findings</span>
          </div>
          {t.findings === 0
            ? <div className="empty" style={{ padding: 20 }}>
                <div className="icon">🛡️</div>
                <h4>No open findings recorded</h4>
                <p>Findings appear here when scans collect evidence that triggers a classification rule. Check the module matrix on your latest scan — failed modules mean incomplete coverage, not safety.</p>
              </div>
            : <div className="row wrap" style={{ gap: 22 }}>
                <Donut data={Object.keys(SEV_COLORS).map(s => ({ value: data.severity[s], color: SEV_COLORS[s] }))} center={[t.findings, 'FINDINGS']} />
                <div style={{ flex: 1, minWidth: 230 }}><SevBars severity={data.severity} /></div>
              </div>}
          <div className="row wrap" style={{ marginTop: 12, gap: 6 }}>
            {Object.entries(data.classification).map(([k, v]) => <span key={k} className="badge b-gray">{k.replace(/_/g, ' ')}: {v}</span>)}
          </div>
        </div>
        <div className="card">
          <h3>Latest module execution</h3>
          <div className="row wrap" style={{ gap: 6 }}>
            {Object.keys(data.module_status).length === 0 && <span className="muted small">No modules executed yet — start a scan from <Link to="/scans">Scans</Link>.</span>}
            {Object.entries(data.module_status).map(([k, v]) => <span key={k} className="badge b-gray" title={`${k}: ${v}`}>{k.replace(/_/g, ' ')} × {v}</span>)}
          </div>
          <h3 style={{ marginTop: 16 }}>Review queue</h3>
          <div className="row" style={{ gap: 10 }}>
            <div className="stat" style={{ flex: 1 }}><div className="v" style={{ color: data.review_items ? 'var(--gold)' : 'var(--green)' }}>{t.review_items}</div><div className="l">Manual-review items</div></div>
            <div className="stat" style={{ flex: 1 }}><div className="v">{t.evidence}</div><div className="l">Evidence records</div></div>
          </div>
        </div>
      </div>

      <div className="grid g2">
        <div className="card pad0">
          <div className="row" style={{ padding: '13px 16px 0' }}><h3 style={{ margin: 0 }}>Recent scans</h3><div className="spacer" /><Link className="small" to="/scans">All scans →</Link></div>
          <div className="tblwrap">
            <table className="tbl">
              <thead><tr><th>Scan</th><th>Target</th><th>Mode</th><th>Status</th><th>When</th></tr></thead>
              <tbody>
                {data.latest_scans.length === 0 && <tr><td colSpan={5}><div className="empty" style={{ padding: 22 }}>No scans yet — launch one from <Link to="/scans">Scans</Link>.</div></td></tr>}
                {data.latest_scans.map(s => (
                  <tr key={s.id} className="click" onClick={() => location.assign(`/scans/${s.id}`)}>
                    <td style={{ fontWeight: 600 }}>{s.name} <DemoBadge demo={s.is_demo} /></td>
                    <td className="mono dim">{s.target}</td>
                    <td><span className={`badge ${s.mode === 'ACTIVE_CONFIRMED' ? 'b-orange' : 'b-teal'}`}>{s.mode === 'ACTIVE_CONFIRMED' ? 'ACTIVE' : 'PASSIVE'}</span></td>
                    <td><ScanStatus s={s.status} /></td>
                    <td className="dim" title={fmtDT(s.created_at)}>{ago(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card pad0">
          <div className="row" style={{ padding: '13px 16px 0' }}><h3 style={{ margin: 0 }}>Recent inventory changes</h3></div>
          <div className="tblwrap">
            <table className="tbl">
              <thead><tr><th>Asset</th><th>Type</th><th>Origin</th><th>Last seen</th></tr></thead>
              <tbody>
                {data.recent_changes.length === 0 && <tr><td colSpan={4}><div className="empty" style={{ padding: 22 }}>Inventory is empty — run a scan to populate it.</div></td></tr>}
                {data.recent_changes.map((a, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.key}</td>
                    <td><span className="badge b-gray">{a.type}</span></td>
                    <td>{a.origin === 'DEMO_SEED' ? <span className="badge b-demo">DEMO</span> : <span className="badge b-teal">SCAN</span>}</td>
                    <td className="dim">{ago(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
