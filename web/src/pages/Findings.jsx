import React, { useCallback, useEffect, useState } from 'react';
import { useApp } from '../App.jsx';
import { api } from '../lib/api.js';
import { useToast, Empty, Loading, usePoll } from '../lib/ui.jsx';
import { FindingsList } from './ScanDetail.jsx';

const SEVS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CLASSES = ['ALL', 'CONFIRMED_FINDING', 'MANUAL_REVIEW', 'HEURISTIC', 'OBSERVED', 'VERIFIED', 'INFERRED'];
const STATUSES = ['ALL', 'OPEN', 'VERIFIED', 'RESOLVED', 'RISK_ACCEPTED', 'FALSE_POSITIVE'];

export default function FindingsPage() {
  const { wsId } = useApp();
  const toast = useToast();
  const [resp, setResp] = useState(null);
  const [sev, setSev] = useState('ALL');
  const [cls, setCls] = useState('ALL');
  const [status, setStatus] = useState('OPEN');
  const [search, setSearch] = useState('');

  const load = useCallback(async () => {
    if (!wsId) return;
    const p = new URLSearchParams({ workspace_id: wsId });
    if (sev !== 'ALL') p.set('severity', sev);
    if (cls !== 'ALL') p.set('classification', cls);
    if (status !== 'ALL') p.set('status', status);
    if (search) p.set('search', search);
    try { setResp(await api.get(`/findings?${p}`)); } catch (e) { toast(e.message, 'err'); }
  }, [wsId, sev, cls, status, search]);
  useEffect(() => { setResp(null); load(); }, [load]);
  usePoll(load, 10000);

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="row wrap">
        <input className="input" style={{ maxWidth: 300 }} placeholder="Search findings…" value={search} onChange={e => setSearch(e.target.value)} />
        <div className="spacer" />
        <span className="muted small">Findings link to evidence; observations never auto-become vulnerabilities.</span>
      </div>
      <div className="grid g3">
        <div>
          <label className="lbl">Severity</label>
          <div className="row wrap" style={{ gap: 5 }}>{SEVS.map(s => <button key={s} className={`btn sm ${sev === s ? 'primary' : 'ghost'}`} onClick={() => setSev(s)}>{s.toLowerCase()}</button>)}</div>
        </div>
        <div>
          <label className="lbl">Classification</label>
          <div className="row wrap" style={{ gap: 5 }}>{CLASSES.map(c => <button key={c} className={`btn sm ${cls === c ? 'primary' : 'ghost'}`} onClick={() => setCls(c)}>{c.replace(/_/g, ' ').toLowerCase()}</button>)}</div>
        </div>
        <div>
          <label className="lbl">Status</label>
          <div className="row wrap" style={{ gap: 5 }}>{STATUSES.map(s => <button key={s} className={`btn sm ${status === s ? 'primary' : 'ghost'}`} onClick={() => setStatus(s)}>{s.replace('_', ' ').toLowerCase()}</button>)}</div>
        </div>
      </div>
      {!resp ? <Loading label="Loading findings…" /> : resp.items.length === 0 ? (
        <div className="card"><Empty icon="🧭" title="No findings match"
          hint="Findings are derived deterministically from collected evidence. Empty here means no evidence triggered a rule — check module coverage on your latest scan before treating this as 'all clear'." /></div>
      ) : <FindingsList resp={resp} reload={load} />}
    </div>
  );
}
