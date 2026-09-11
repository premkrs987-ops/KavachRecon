import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useApp } from '../App.jsx';
import { api, ago, fmtDT } from '../lib/api.js';
import { Modal, Empty, Loading, useToast, ScanStatus, ModeBadge, DemoBadge, Confirm, usePoll } from '../lib/ui.jsx';

const MODULES = [
  ['dns_enum', 'DNS enumeration', 'A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/PTR'], ['email_security', 'SPF / DMARC / DKIM', 'mail policy discovery'],
  ['subdomain_brute', 'Subdomain dictionary', 'DNS resolution of curated wordlist'], ['dns_analysis', 'Wildcard & dangling CNAME', 'zone behaviour analysis'],
  ['ct_logs', 'Certificate Transparency', 'crt.sh public log search'], ['whois_intel', 'WHOIS / RDAP', 'registration intelligence'],
  ['asn_mapping', 'ASN / CIDR mapping', 'Team Cymru + ARIN'], ['historical_dns', 'Historical DNS', 'public archives'],
  ['url_archive', 'Archive URLs', 'Internet Archive CDX'],
  ['host_discovery', 'Host discovery — active', 'TCP reachability probes'], ['port_scan', 'Port & service scan — active', 'top ports, protocol-aware'],
  ['http_probe', 'HTTP/HTTPS probing — active', 'status, redirects, headers'], ['tls_analysis', 'TLS analysis — active', 'cert & protocol inspection'],
  ['tech_fingerprint', 'Technology fingerprinting', 'evidence-based only'], ['waf_cdn', 'WAF / CDN detection', 'header signatures'],
  ['security_posture', 'Security posture', 'headers / cookies / TLS'], ['robots_sitemap', 'robots.txt & sitemap', 'directive parsing'],
  ['endpoint_discovery', 'Endpoint discovery', 'link extraction + classification'], ['js_intel', 'JavaScript intelligence', 'routes, refs, secret patterns'],
  ['cloud_intel', 'Cloud intelligence', 'evidence-based signals'], ['screenshot', 'Screenshots', 'requires renderer backend'],
];
const PASSIVE_DEFAULT = ['dns_enum', 'email_security', 'subdomain_brute', 'dns_analysis', 'ct_logs', 'whois_intel', 'asn_mapping', 'historical_dns', 'url_archive'];
const ACTIVE_DEFAULT = [...PASSIVE_DEFAULT, 'host_discovery', 'port_scan', 'http_probe', 'tls_analysis', 'tech_fingerprint', 'waf_cdn', 'security_posture', 'robots_sitemap', 'endpoint_discovery', 'js_intel', 'cloud_intel'];

export default function Scans() {
  const { wsId } = useApp();
  const toast = useToast();
  const [scans, setScans] = useState(null);
  const [filter, setFilter] = useState('ALL');
  const [launch, setLaunch] = useState(false);
  const [confirmDel, setConfirmDel] = useState(null);
  const [busyDel, setBusyDel] = useState(false);

  const load = useCallback(async () => {
    if (!wsId) return;
    try { setScans(await api.get(`/scans?workspace_id=${wsId}`)); } catch (e) { toast(e.message, 'err'); }
  }, [wsId]);
  useEffect(() => { setScans(null); load(); }, [load]);
  usePoll(load, 3500);

  const filtered = (scans || []).filter(s => filter === 'ALL' ? true : filter === 'RUNNING' ? ['QUEUED', 'RUNNING'].includes(s.status) : s.status === filter);

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="row wrap">
        <div className="grow">
          <div style={{ fontWeight: 700, fontSize: 15 }}>Scans</div>
          <div className="muted small">Passive scans use public data only. Active scans require target-level authorization plus explicit confirmation here — both are audited.</div>
        </div>
        <button className="btn primary" onClick={() => setLaunch(true)} disabled={!wsId}>▶ New scan</button>
      </div>
      <div className="row wrap" style={{ gap: 6 }}>
        {['ALL', 'RUNNING', 'COMPLETED', 'COMPLETED_WITH_FAILURES', 'FAILED', 'CANCELLED'].map(f => (
          <button key={f} className={`btn sm ${filter === f ? 'primary' : 'ghost'}`} onClick={() => setFilter(f)}>{f.replace(/_/g, ' ').toLowerCase()}</button>
        ))}
      </div>
      <div className="card pad0">
        {!scans ? <Loading label="Loading scans…" /> : filtered.length === 0 ? (
          <Empty icon="🛰️" title={filter === 'ALL' ? 'No scans yet' : `No ${filter.toLowerCase().replace(/_/g, ' ')} scans`}
            hint="Launch a unified scan: subdomains, DNS, WHOIS, CT logs, ports, web, TLS, technologies, endpoints, JS secrets — every module reports its own status honestly."
            action={<button className="btn primary" onClick={() => setLaunch(true)}>Launch first scan</button>} />
        ) : (
          <div className="tblwrap"><table className="tbl">
            <thead><tr><th>Scan</th><th>Target</th><th>Mode</th><th>Modules</th><th>Findings</th><th>Status</th><th>Started</th><th></th></tr></thead>
            <tbody>
              {filtered.map(s => {
                const mods = s.summary?.modules || {};
                return (
                  <tr key={s.id} className="click" onClick={() => location.assign(`/scans/${s.id}`)}>
                    <td style={{ fontWeight: 600, maxWidth: 260 }}>
                      {s.name} <DemoBadge demo={s.is_demo} />
                      <div className="muted small mono">{s.id.slice(-8)}</div>
                    </td>
                    <td className="mono dim">{s.target_identifier}</td>
                    <td><ModeBadge m={s.mode} /></td>
                    <td className="dim small">{mods.COMPLETED ?? 0} ok{mods.FAILED ? ` · ${mods.FAILED} failed` : ''}</td>
                    <td style={{ fontWeight: 700 }}>{s.summary?.totals?.findings ?? '—'}</td>
                    <td><ScanStatus s={s.status} /></td>
                    <td className="dim" title={fmtDT(s.created_at)}>{ago(s.created_at)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      {['QUEUED', 'RUNNING'].includes(s.status)
                        ? <button className="btn sm danger" onClick={async () => { await api.post(`/scans/${s.id}/cancel`); toast('Cancellation requested — engine stops between operations'); load(); }}>Cancel</button>
                        : <button className="btn sm ghost" onClick={() => setConfirmDel(s)}>🗑</button>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        )}
      </div>
      {launch && <LaunchModal onClose={() => setLaunch(false)} onLaunched={(id) => { setLaunch(false); load(); location.assign(`/scans/${id}`); }} />}
      {confirmDel && (
        <Confirm title="Delete scan?" danger busy={busyDel} confirmLabel="Delete scan"
          message={`Delete “${confirmDel.name}” and all its collected records (modules, evidence, findings from this scan). The audit trail entry remains.`}
          onClose={() => setConfirmDel(null)}
          onConfirm={async () => { setBusyDel(true); try { await api.del(`/scans/${confirmDel.id}`); toast('Scan deleted'); setConfirmDel(null); load(); } catch (e) { toast(e.message, 'err'); } finally { setBusyDel(false); } }} />
      )}
    </div>
  );
}

function LaunchModal({ onClose, onLaunched }) {
  const { wsId } = useApp();
  const toast = useToast();
  const [targets, setTargets] = useState([]);
  const [targetId, setTargetId] = useState('');
  const [name, setName] = useState('');
  const [mode, setMode] = useState('PASSIVE_ONLY');
  const [selected, setSelected] = useState(new Set(PASSIVE_DEFAULT));
  const [confirmActive, setConfirmActive] = useState(false);
  const [topPorts, setTopPorts] = useState('quick');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get(`/targets?workspace_id=${wsId}`).then(ts => { setTargets(ts); if (ts[0]) setTargetId(ts[0].id); });
  }, [wsId]);
  const target = targets.find(t => t.id === targetId);
  const activeAllowed = target?.active_confirmed === 1;

  useEffect(() => {
    setSelected(new Set(mode === 'ACTIVE_CONFIRMED' ? ACTIVE_DEFAULT : PASSIVE_DEFAULT));
    setConfirmActive(false);
  }, [mode]);

  const launchScan = async () => {
    setBusy(true);
    try {
      const s = await api.post('/scans', {
        target_id: targetId, name: name || `Scan ${new Date().toLocaleString()}`,
        mode, confirm_active: mode === 'ACTIVE_CONFIRMED' ? true : undefined,
        config: { modules: [...selected], top_ports: topPorts },
      });
      toast(`Scan launched — ${selected.size} modules`);
      onLaunched(s.id);
    } catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };

  return (
    <Modal wide title="Launch new scan" onClose={onClose} footer={
      <>
        <button className="btn ghost" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!targetId || busy || selected.size === 0 || (mode === 'ACTIVE_CONFIRMED' && !confirmActive)} onClick={launchScan}>
          {busy ? <span className="spinner" /> : mode === 'ACTIVE_CONFIRMED' ? 'Confirm & launch ACTIVE scan' : 'Launch passive scan'}
        </button>
      </>
    }>
      <div className="grid g2">
        <div className="field"><label className="lbl">Authorized target</label>
          <select className="input" value={targetId} onChange={e => setTargetId(e.target.value)}>
            {targets.length === 0 && <option value="">— add a target first —</option>}
            {targets.map(t => <option key={t.id} value={t.id}>{t.identifier} ({t.type}){t.active_confirmed ? ' ✓active' : ''}</option>)}
          </select>
        </div>
        <div className="field"><label className="lbl">Scan name</label>
          <input className="input" placeholder={`e.g. Baseline surface map — ${new Date().toISOString().slice(0, 10)}`} value={name} onChange={e => setName(e.target.value)} />
        </div>
      </div>
      <div className="field">
        <label className="lbl">Scan mode</label>
        <div className="grid g2" style={{ gap: 8 }}>
          <button className={`btn ${mode === 'PASSIVE_ONLY' ? 'primary' : ''}`} style={{ justifyContent: 'flex-start', flexDirection: 'column', alignItems: 'flex-start', gap: 2, padding: 11 }}
            onClick={() => setMode('PASSIVE_ONLY')}>
            <b>PASSIVE-ONLY</b><span className="small" style={{ fontWeight: 400, opacity: .8 }}>Public data + DNS only. No packets to the target.</span>
          </button>
          <button className={`btn ${mode === 'ACTIVE_CONFIRMED' ? 'primary' : ''}`} style={{ justifyContent: 'flex-start', flexDirection: 'column', alignItems: 'flex-start', gap: 2, padding: 11, opacity: activeAllowed ? 1 : .6 }}
            onClick={() => activeAllowed ? setMode('ACTIVE_CONFIRMED') : toast('This target has not been confirmed for active reconnaissance — open Targets → Manage to authorize it.', 'warn')}>
            <b>ACTIVE (confirmed)</b><span className="small" style={{ fontWeight: 400, opacity: .8 }}>Ports, HTTP, TLS — requires explicit confirmation.</span>
          </button>
        </div>
      </div>
      {mode === 'ACTIVE_CONFIRMED' && (
        <div className="callout danger" style={{ marginBottom: 12 }}>
          <label className="checkline">
            <input type="checkbox" checked={confirmActive} onChange={e => setConfirmActive(e.target.checked)} disabled={!activeAllowed} />
            <span><b>I confirm</b> I am authorized to perform active reconnaissance against <b className="mono">{target?.identifier}</b>, including TCP connections, HTTP requests and TLS handshakes. {activeAllowed ? '' : ' ⚠ This target lacks target-level active confirmation.'}</span>
          </label>
        </div>
      )}
      <label className="lbl">Modules ({selected.size} selected) — every module reports its own status; failures never become “no findings”</label>
      <div style={{ maxHeight: 260, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 9, padding: '8px 10px', display: 'grid', gap: 4 }}>
        {MODULES.map(([key, label, hint]) => {
          const isActive = ['host_discovery', 'port_scan', 'http_probe', 'tls_analysis'].includes(key);
          const activeLocked = isActive && mode !== 'ACTIVE_CONFIRMED';
          return (
            <label key={key} className="checkline" style={{ opacity: activeLocked ? .45 : 1, padding: '3px 2px' }}>
              <input type="checkbox" checked={selected.has(key)} disabled={activeLocked}
                onChange={e => { const n = new Set(selected); e.target.checked ? n.add(key) : n.delete(key); setSelected(n); }} />
              <span><b style={{ color: 'var(--ink)' }}>{label}</b> <span className="muted"> — {hint}</span>{activeLocked && <span className="badge b-gold" style={{ marginLeft: 6 }}>needs active mode</span>}</span>
            </label>
          );
        })}
      </div>
      {selected.has('port_scan') && (
        <div className="field" style={{ marginTop: 12 }}>
          <label className="lbl">Port scan depth</label>
          <select className="input" value={topPorts} onChange={e => setTopPorts(e.target.value)}>
            <option value="quick">Quick — top 26 service ports</option>
            <option value="extended">Extended — top 65 service ports (slower)</option>
          </select>
        </div>
      )}
      <div className="callout" style={{ marginTop: 10 }}>Rate limits: token bucket, global 25 ops/s, 5 ops/s per host. Scan controls (cancel) work between operations.</div>
    </Modal>
  );
}
