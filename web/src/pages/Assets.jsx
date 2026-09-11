import React, { useCallback, useEffect, useState } from 'react';
import { useApp } from '../App.jsx';
import { api, ago } from '../lib/api.js';
import { useToast, Empty, Loading, Drawer, Modal, Confirm, usePoll } from '../lib/ui.jsx';
import { EvidenceCard } from './ScanDetail.jsx';

const TYPES = ['ALL', 'DOMAIN', 'SUBDOMAIN', 'IP', 'HOST', 'PORT', 'SERVICE', 'URL', 'ENDPOINT', 'TECHNOLOGY', 'CERT', 'JS_RESOURCE', 'CLOUD', 'CIDR'];
const TYPE_COLORS = { DOMAIN: 'b-purple', SUBDOMAIN: 'b-teal', IP: 'b-blue', HOST: 'b-blue', PORT: 'b-orange', SERVICE: 'b-red', URL: 'b-gray', ENDPOINT: 'b-gold', TECHNOLOGY: 'b-green', CERT: 'b-purple', JS_RESOURCE: 'b-teal', CLOUD: 'b-blue', CIDR: 'b-gray' };

export default function Assets() {
  const { wsId } = useApp();
  const toast = useToast();
  const [data, setData] = useState(null);
  const [type, setType] = useState('ALL');
  const [search, setSearch] = useState('');
  const [origin, setOrigin] = useState('');
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [confirmFp, setConfirmFp] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!wsId) return;
    const p = new URLSearchParams({ workspace_id: wsId, limit: 400 });
    if (type !== 'ALL') p.set('type', type);
    if (search) p.set('search', search);
    if (origin) p.set('origin', origin);
    try { setData(await api.get(`/assets?${p}`)); } catch (e) { toast(e.message, 'err'); }
  }, [wsId, type, search, origin]);
  useEffect(() => { setData(null); load(); }, [load]);
  usePoll(load, 10000);

  const open = async (a) => { setSel(a); setDetail(await api.get(`/assets/${a.id}`)); };
  const markFp = async () => {
    setBusy(true);
    try { await api.patch(`/assets/${confirmFp.id}`, { verification: 'FALSE_POSITIVE' }); toast('Asset marked false positive and hidden from inventory'); setConfirmFp(null); setSel(null); load(); }
    catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="row wrap">
        <input className="input" style={{ maxWidth: 320 }} placeholder="Search inventory…" value={search} onChange={e => setSearch(e.target.value)} />
        <select className="input" style={{ maxWidth: 170 }} value={origin} onChange={e => setOrigin(e.target.value)}>
          <option value="">All origins</option><option value="SCAN">Scan-collected</option><option value="DEMO_SEED">Demo data</option>
        </select>
        <div className="spacer" />
        {data && <span className="muted small">{data.total} assets (de-duplicated, workspace-wide)</span>}
      </div>
      <div className="row wrap" style={{ gap: 6 }}>
        {TYPES.map(t => (
          <button key={t} className={`btn sm ${type === t ? 'primary' : 'ghost'}`} onClick={() => setType(t)}>
            {t.toLowerCase()}
            {data && t !== 'ALL' && data.counts?.find(c => c.type === t) ? <span className="pillcount" style={{ marginLeft: 5 }}>{data.counts.find(c => c.type === t).n}</span> : null}
          </button>
        ))}
      </div>

      <div className="card pad0">
        {!data ? <Loading label="Loading inventory…" /> : data.items.length === 0 ? (
          <Empty icon="🗂️" title="Inventory is empty" hint="Assets appear here as scans discover them — de-duplicated with first/last-seen tracking, source and evidence links. Run a scan or add demo data." />
        ) : (
          <div className="tblwrap"><table className="tbl">
            <thead><tr><th>Asset</th><th>Type</th><th>Status</th><th>Origin</th><th>Confidence</th><th>First seen</th><th>Last seen</th><th>Evidence</th></tr></thead>
            <tbody>{data.items.map(a => (
              <tr key={a.id} className="click" onClick={() => open(a)}>
                <td className="mono" style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.key}</td>
                <td><span className={`badge ${TYPE_COLORS[a.type] || 'b-gray'}`}>{a.type}</span></td>
                <td><span className={`badge ${a.status === 'ACTIVE' ? 'b-green' : a.status === 'UNREACHABLE' ? 'b-gray' : 'b-gold'}`}>{a.status}</span></td>
                <td>{a.origin === 'DEMO_SEED' ? <span className="badge b-demo">DEMO</span> : <span className="badge b-teal">SCAN</span>}</td>
                <td><span className={`badge ${a.confidence === 'HIGH' ? 'b-green' : a.confidence === 'MEDIUM' ? 'b-blue' : 'b-gold'}`}>{a.confidence}</span></td>
                <td className="dim small">{ago(a.first_seen)}</td>
                <td className="dim small">{ago(a.last_seen)}</td>
                <td className="mono">{a.evidence_count || 0}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </div>

      {sel && detail && (
        <Drawer title={<span className="mono" style={{ wordBreak: 'break-all' }}>{detail.key}</span>} subtitle={`${detail.type} · origin ${detail.origin} · ${detail.verification}`}
          onClose={() => setSel(null)}>
          <div className="kv" style={{ marginBottom: 14 }}>
            <div className="k">Status</div><div><span className={`badge ${detail.status === 'ACTIVE' ? 'b-green' : 'b-gray'}`}>{detail.status}</span></div>
            <div className="k">First seen</div><div className="small">{new Date(detail.first_seen).toLocaleString()}</div>
            <div className="k">Last seen</div><div className="small">{new Date(detail.last_seen).toLocaleString()}</div>
            <div className="k">Confidence</div><div>{detail.confidence}</div>
            <div className="k">Value</div><div className="mono small prewrap">{String(detail.value)}</div>
          </div>
          <div className="row" style={{ marginBottom: 14 }}>
            <button className="btn sm" onClick={() => setConfirmFp(detail)}>Mark false positive</button>
            {detail.verification === 'UNVERIFIED' && <button className="btn sm ok" onClick={async () => { await api.patch(`/assets/${detail.id}`, { verification: 'VERIFIED' }); toast('Asset verified'); setSel(null); load(); }}>✓ Verify</button>}
          </div>
          {(detail.edges_in?.length > 0 || detail.edges_out?.length > 0) && (
            <>
              <label className="lbl">Relationships</label>
              <div className="row wrap" style={{ gap: 5, marginBottom: 14 }}>
                {detail.edges_in.map(e => <span key={'i' + e.id} className="badge b-gray">← {e.relation} · <span className="mono">{e.key}</span></span>)}
                {detail.edges_out.map(e => <span key={'o' + e.id} className="badge b-gray">{e.relation} → <span className="mono">{e.key}</span></span>)}
              </div>
            </>
          )}
          {detail.findings?.length > 0 && (
            <>
              <label className="lbl">Findings on this asset</label>
              <div style={{ marginBottom: 14 }}>
                {detail.findings.map(f => <div key={f.id} className="small" style={{ marginBottom: 4 }}><span className={`badge ${f.severity === 'HIGH' ? 'b-red' : 'b-orange'}`}>{f.severity}</span> {f.title}</div>)}
              </div>
            </>
          )}
          <label className="lbl">Evidence ({detail.evidence.length})</label>
          {detail.evidence.map(ev => <EvidenceCard key={ev.id} ev={ev} />)}
        </Drawer>
      )}
      {confirmFp && <Confirm title="Mark asset as false positive?" danger busy={busy} confirmLabel="Hide asset"
        message={`“${confirmFp.key}” will be hidden from the inventory and excluded from counts. This is reversible by an operator in the database and is recorded in the audit trail.`}
        onClose={() => setConfirmFp(null)} onConfirm={markFp} />}
    </div>
  );
}
