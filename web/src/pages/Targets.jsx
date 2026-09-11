import React, { useCallback, useEffect, useState } from 'react';
import { useApp } from '../App.jsx';
import { api, fmtDT } from '../lib/api.js';
import { Modal, Confirm, Empty, Loading, useToast, DemoBadge, usePoll } from '../lib/ui.jsx';

const ScopeBadge = ({ r }) => (
  <span className={`badge ${r.kind === 'INCLUDE' ? 'b-green' : 'b-red'}`} title={r.reason || ''}>
    {r.kind === 'INCLUDE' ? 'ALLOW' : 'EXCLUDE'} · {r.pattern_type.toLowerCase()} · {r.pattern}
  </span>
);

export default function Targets() {
  const { wsId } = useApp();
  const toast = useToast();
  const [targets, setTargets] = useState(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState(null); // target being edited (drawer modal)
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!wsId) return;
    try { setTargets(await api.get(`/targets?workspace_id=${wsId}`)); } catch (e) { toast(e.message, 'err'); }
  }, [wsId]);
  useEffect(() => { setTargets(null); load(); }, [load]);
  usePoll(load, 8000);

  if (!targets) return <Loading label="Loading targets…" />;

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="row wrap">
        <div className="grow">
          <div style={{ fontWeight: 700, fontSize: 15 }}>Authorized targets</div>
          <div className="muted small">Every scan is enforced against the target scope. Active reconnaissance additionally requires explicit confirmation.</div>
        </div>
        <button className="btn primary" onClick={() => setCreating(true)}>＋ Add target</button>
      </div>

      {targets.length === 0 ? (
        <div className="card"><Empty icon="🎯" title="No targets yet"
          hint="Add an authorized domain, IP or CIDR. KavachRecon only ever scans what you explicitly authorize here — scope rules are enforced before every network operation."
          action={<button className="btn primary" onClick={() => setCreating(true)}>Add your first target</button>} /></div>
      ) : (
        <div className="grid g2">
          {targets.map(t => (
            <div key={t.id} className="card">
              <div className="row wrap">
                <div className="grow" style={{ minWidth: 0 }}>
                  <div className="row" style={{ gap: 8 }}>
                    <span style={{ fontWeight: 800, fontSize: 15.5 }} className="mono">{t.identifier}</span>
                    <span className="badge b-purple">{t.type}</span>
                    {t.active_confirmed === 1 && <span className="badge b-orange" title="Active recon confirmed for this target">ACTIVE OK</span>}
                  </div>
                  <div className="muted small" style={{ marginTop: 3 }}>{t.label || 'No label'} {t.notes ? `— ${t.notes}` : ''}</div>
                </div>
                <button className="btn sm" onClick={() => setEditing(t)}>Manage</button>
                <button className="btn sm danger" onClick={() => setConfirmDelete(t)}>✕</button>
              </div>
              <div className="row wrap" style={{ gap: 5, marginTop: 10 }}>
                <span className="badge b-gray">{t.scan_count} scan{t.scan_count === 1 ? '' : 's'}</span>
                {t.last_scan && <span className="badge b-gray">last: {t.last_scan.status?.replace(/_/g, ' ').toLowerCase()} · {fmtDT(t.last_scan.created_at)}</span>}
                <span className="badge b-gray">{t.scope_rules?.length || 0} scope rule{t.scope_rules?.length === 1 ? '' : 's'}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {creating && <TargetModal onClose={() => setCreating(false)} onSaved={() => { setCreating(false); load(); }} wsId={wsId} />}
      {editing && <ManageModal target={editing} onClose={() => setEditing(null)} onChanged={load} toast={toast} />}
      {confirmDelete && (
        <Confirm title="Delete target?" danger busy={busy} confirmLabel="Delete target"
          message={`This permanently deletes target “${confirmDelete.identifier}”, its scope rules and its scans (including collected evidence). This cannot be undone.`}
          onClose={() => setConfirmDelete(null)}
          onConfirm={async () => {
            setBusy(true);
            try { await api.del(`/targets/${confirmDelete.id}`); toast('Target deleted'); setConfirmDelete(null); load(); }
            catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
          }} />
      )}
    </div>
  );
}

function TargetModal({ onClose, onSaved, wsId }) {
  const toast = useToast();
  const [identifier, setIdentifier] = useState('');
  const [type, setType] = useState('AUTO');
  const [label, setLabel] = useState('');
  const [notes, setNotes] = useState('');
  const [activeConfirmed, setActiveConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      const t = await api.post('/targets', { workspace_id: wsId, identifier, type, label, notes });
      if (activeConfirmed) await api.patch(`/targets/${t.id}`, { label, notes: `${notes} [active recon authorized by operator at ${new Date().toISOString()}]` }).then(async () => {
        await api.post(`/targets/${t.id}/rules`, { kind: 'INCLUDE', pattern: t.identifier, pattern_type: t.type === 'DOMAIN' ? 'DOMAIN' : t.type === 'IP' ? 'IP' : 'CIDR', reason: 'Target authorized by operator' });
      });
      toast(`Target “${t.identifier}” added`);
      onSaved();
    } catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };

  return (
    <Modal title="Add authorized target" onClose={onClose} footer={
      <>
        <button className="btn ghost" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!identifier.trim() || busy} onClick={save}>{busy ? <span className="spinner" /> : 'Add target'}</button>
      </>
    }>
      <div className="field"><label className="lbl">Identifier — domain, IP or CIDR</label>
        <input className="input mono" placeholder="e.g. example.com · 93.184.216.34 · 192.168.1.0/24" value={identifier} onChange={e => setIdentifier(e.target.value)} autoFocus />
      </div>
      <div className="field"><label className="lbl">Type</label>
        <select className="input" value={type} onChange={e => setType(e.target.value)}>
          <option value="AUTO">Auto-detect</option><option value="DOMAIN">Domain</option><option value="IP">IP address</option><option value="CIDR">CIDR range</option>
        </select>
      </div>
      <div className="field"><label className="lbl">Label</label><input className="input" placeholder='e.g. "Main corporate site"' value={label} onChange={e => setLabel(e.target.value)} /></div>
      <div className="field"><label className="lbl">Authorisation notes</label><textarea className="input" rows={2} placeholder="Who authorized this? Ticket ref? Written permission location…" value={notes} onChange={e => setNotes(e.target.value)} /></div>
      <label className="checkline" style={{ marginTop: 4 }}>
        <input type="checkbox" checked={activeConfirmed} onChange={e => setActiveConfirmed(e.target.checked)} />
        <span><b>I confirm active reconnaissance authorization</b> for this target. Without this, only passive scans (public data + DNS) can run; active modules will be reported as NOT_APPLICABLE.</span>
      </label>
      <div className="callout" style={{ marginTop: 12 }}>Only add targets you are <b>explicitly authorized</b> to assess. Every scan against this target is recorded in the audit trail with your identity.</div>
    </Modal>
  );
}

function ManageModal({ target: t, onClose, onChanged, toast }) {
  const [rules, setRules] = useState(t.scope_rules || []);
  const [label, setLabel] = useState(t.label);
  const [notes, setNotes] = useState(t.notes);
  const [activeOk, setActiveOk] = useState(t.active_confirmed === 1);
  const [newRule, setNewRule] = useState({ kind: 'EXCLUDE', pattern: '', pattern_type: 'DOMAIN', reason: '' });
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    const list = await api.get(`/targets?workspace_id=${t.workspace_id}`);
    const me = list.find(x => x.id === t.id);
    setRules(me.scope_rules); setActiveOk(me.active_confirmed === 1);
    onChanged();
  };
  const saveMeta = async () => {
    setBusy(true);
    try {
      await api.patch(`/targets/${t.id}`, { label, notes });
      const want = activeOk ? 1 : 0;
      const list = await api.get(`/targets?workspace_id=${t.workspace_id}`);
      const cur = list.find(x => x.id === t.id).active_confirmed;
      if (want !== cur) {
        await api.patch(`/targets/${t.id}`, { label, notes: want ? `${notes} [active recon authorized by operator at ${new Date().toISOString()}]`.trim() : notes });
        if (want) toast('Active reconnaissance CONFIRMED for this target');
        else toast('Active confirmation revoked — passive scans only', 'warn');
      } else toast('Target updated');
      await reload();
    } catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };
  const addRule = async () => {
    if (!newRule.pattern.trim()) return;
    try { await api.post(`/targets/${t.id}/rules`, newRule); setNewRule({ ...newRule, pattern: '', reason: '' }); await reload(); toast('Scope rule added'); }
    catch (e) { toast(e.message, 'err'); }
  };
  const delRule = async (rid) => {
    try { await api.del(`/targets/${t.id}/rules/${rid}`); await reload(); toast('Scope rule removed'); }
    catch (e) { toast(e.message, 'err'); }
  };

  return (
    <Modal wide title={<span>Manage <span className="mono">{t.identifier}</span></span>} onClose={onClose} footer={
      <><button className="btn ghost" onClick={onClose}>Close</button>
        <button className="btn primary" disabled={busy} onClick={saveMeta}>{busy ? <span className="spinner" /> : 'Save changes'}</button></>
    }>
      <div className="grid g2">
        <div className="field"><label className="lbl">Label</label><input className="input" value={label} onChange={e => setLabel(e.target.value)} /></div>
        <div className="field"><label className="lbl">Authorisation notes</label><input className="input" value={notes} onChange={e => setNotes(e.target.value)} /></div>
      </div>
      <label className="checkline" style={{ margin: '4px 0 16px' }}>
        <input type="checkbox" checked={activeOk} onChange={e => setActiveOk(e.target.checked)} />
        <span><b>Active reconnaissance authorized</b> — allows port scanning, HTTP probing and TLS handshakes against this target when a scan is explicitly created in ACTIVE mode.</span>
      </label>
      <label className="lbl">Scope rules — enforced before every network operation ({rules.length})</label>
      <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
        {rules.length === 0 && <span className="muted small">No extra rules. The target itself ({t.identifier}) is always in scope; add INCLUDE/EXCLUDE rules to refine.</span>}
        {rules.map(r => (
          <span key={r.id} className="row" style={{ gap: 4 }}>
            <ScopeBadge r={r} />
            <button className="btn sm ghost" style={{ padding: '1px 6px' }} onClick={() => delRule(r.id)} title="Remove rule">✕</button>
          </span>
        ))}
      </div>
      <div className="grid g4" style={{ gap: 8 }}>
        <select className="input" value={newRule.kind} onChange={e => setNewRule({ ...newRule, kind: e.target.value })}>
          <option value="EXCLUDE">EXCLUDE</option><option value="INCLUDE">INCLUDE</option>
        </select>
        <select className="input" value={newRule.pattern_type} onChange={e => setNewRule({ ...newRule, pattern_type: e.target.value })}>
          <option value="DOMAIN">Domain</option><option value="IP">IP</option><option value="CIDR">CIDR</option><option value="WILDCARD">Wildcard</option>
        </select>
        <input className="input mono" placeholder="pattern" value={newRule.pattern} onChange={e => setNewRule({ ...newRule, pattern: e.target.value })} />
        <button className="btn" onClick={addRule}>＋ Add rule</button>
      </div>
      <input className="input" style={{ marginTop: 8 }} placeholder="reason (recorded in audit trail & PDF §2)" value={newRule.reason} onChange={e => setNewRule({ ...newRule, reason: e.target.value })} />
      <div className="callout warn" style={{ marginTop: 12 }}>Excludes always win — even if data references them (e.g. a discovered subdomain), the engine will never contact them.</div>
    </Modal>
  );
}
