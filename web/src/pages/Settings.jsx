import React, { useCallback, useEffect, useState } from 'react';
import { useApp } from '../App.jsx';
import { api } from '../lib/api.js';
import { useToast, Modal, Confirm, Loading, usePoll } from '../lib/ui.jsx';

export default function Settings() {
  const toast = useToast();
  const { user, workspaces, refreshWorkspaces } = useApp();
  const [settings, setSettings] = useState(null);
  const [key, setKey] = useState('');
  const [model, setModel] = useState('gemini-2.0-flash');
  const [busy, setBusy] = useState(false);
  const [confirmPurge, setConfirmPurge] = useState(false);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState(null);
  const [deleting, setDeleting] = useState(null);

  const load = useCallback(() => api.get('/settings').then(setSettings).catch(() => { }), []);
  useEffect(() => { load(); }, [load]);

  const save = async () => {
    setBusy(true);
    try { const s = await api.put('/settings', { gemini_api_key: key === '' ? undefined : key, gemini_model: model }); setSettings(s); setKey(''); toast('Settings saved'); }
    catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };
  const testAi = async () => {
    setBusy(true);
    try { const r = await api.post('/settings/ai/test'); toast(r.ok ? r.message : `${r.message}`, r.ok ? 'ok' : 'err'); }
    catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };
  const purge = async () => {
    setBusy(true);
    try { const r = await api.post('/demo/purge'); toast(r.purged ? 'Demo data purged — dashboards now show only real scan data' : 'No demo data present'); setConfirmPurge(false); await refreshWorkspaces(); }
    catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };

  if (!settings) return <Loading />;
  return (
    <div style={{ display: 'grid', gap: 16, maxWidth: 860 }}>
      <div className="card">
        <h3>Gemini AI integration</h3>
        <div className="muted small" style={{ marginBottom: 12 }}>Used for evidence-grounded executive summaries, finding explanations and natural-language querying. The key is stored server-side and never exposed to the browser beyond a masked preview. AI features obey <b>NO EVIDENCE = NO CLAIM</b>.</div>
        <div className="grid g2">
          <div className="field"><label className="lbl">API key {settings.gemini_api_key_set && <span className="badge b-green">configured · {settings.gemini_api_key}</span>}</label>
            <input className="input mono" type="password" placeholder={settings.gemini_api_key_set ? 'leave blank to keep current key' : 'AIza…'} value={key} onChange={e => setKey(e.target.value)} />
          </div>
          <div className="field"><label className="lbl">Model</label>
            <select className="input" value={model || settings.gemini_model} onChange={e => setModel(e.target.value)}>
              {['gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-1.5-flash', 'gemini-1.5-pro'].map(m => <option key={m}>{m}</option>)}
            </select>
          </div>
        </div>
        <div className="row">
          <button className="btn primary" disabled={busy} onClick={save}>{busy ? <span className="spinner" /> : 'Save'}</button>
          <button className="btn" disabled={busy || !settings.gemini_api_key_set} onClick={testAi}>Test reachability</button>
        </div>
        <div className="callout" style={{ marginTop: 12 }}>If the test reports the endpoint is unreachable, this deployment has no outbound HTTPS to <span className="mono">generativelanguage.googleapis.com</span> — everything else keeps working and AI outputs stay honestly unavailable.</div>
      </div>

      <div className="card">
        <h3>Workspaces</h3>
        <div className="muted small" style={{ marginBottom: 10 }}>Workspaces isolate targets, scans, assets and findings. Demo data lives in its own workspace.</div>
        <div className="tblwrap"><table className="tbl">
          <thead><tr><th>Name</th><th>Targets</th><th>Scans</th><th>Kind</th><th></th></tr></thead>
          <tbody>
            {workspaces.map(w => (
              <tr key={w.id}>
                <td style={{ fontWeight: 600 }}>{w.name}<div className="muted small" style={{ maxWidth: 340 }}>{w.description?.slice(0, 110)}</div></td>
                <td className="mono">{w.targets}</td><td className="mono">{w.scans}</td>
                <td>{w.is_demo ? <span className="badge b-demo">DEMO</span> : <span className="badge b-teal">LIVE</span>}</td>
                <td className="row" style={{ gap: 5, justifyContent: 'flex-end' }}>
                  <button className="btn sm" onClick={() => setEditing(w)}>Rename</button>
                  {!w.is_demo && <button className="btn sm danger" onClick={() => setDeleting(w)}>Delete</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
        <button className="btn" style={{ marginTop: 10 }} onClick={() => setCreating(true)}>＋ New workspace</button>
      </div>

      <div className="card">
        <h3>Demo data</h3>
        <div className="muted small" style={{ marginBottom: 10 }}>KavachRecon ships with a clearly-labelled demo workspace so the UI is explorable immediately. Demo records are tagged <span className="mono">DEMO_SEED</span> and never mix with live scan output.</div>
        <button className="btn danger" onClick={() => setConfirmPurge(true)}>Purge demo data</button>
      </div>

      <div className="card">
        <h3>About</h3>
        <div className="kv">
          <div className="k">Platform</div><div>KavachRecon Intelligence Platform v1.0</div>
          <div className="k">Built by</div><div><b>@premkrs</b></div>
          <div className="k">Principle</div><div>REAL DATA → NORMALIZATION → EVIDENCE → VERIFICATION → CLASSIFICATION → RISK → REPORT. Never EMPTY DATA → AI GUESS → FAKE FINDING.</div>
          <div className="k">Signed in as</div><div>{user?.name} ({user?.email})</div>
        </div>
      </div>

      {creating && <WsModal onClose={() => setCreating(false)} onSaved={async () => { setCreating(false); await refreshWorkspaces(); toast('Workspace created'); }} toast={toast} />}
      {editing && <WsModal ws={editing} onClose={() => setEditing(null)} onSaved={async () => { setEditing(null); await refreshWorkspaces(); toast('Workspace updated'); }} toast={toast} />}
      {deleting && (
        <Confirm title={`Delete workspace “${deleting.name}”?`} danger busy={busy} confirmLabel="Delete permanently"
          message="Deletes ALL targets, scans, assets, findings and evidence in this workspace. The audit trail remains. This cannot be undone."
          onClose={() => setDeleting(null)}
          onConfirm={async () => { setBusy(true); try { await api.del(`/workspaces/${deleting.id}`); setDeleting(null); await refreshWorkspaces(); toast('Workspace deleted'); } catch (e) { toast(e.message, 'err'); } finally { setBusy(false); } }} />
      )}
      {confirmPurge && (
        <Confirm title="Purge all demo data?" danger busy={busy} confirmLabel="Purge demo data"
          message="Removes the demo workspace and any demo-tagged records everywhere. Real scans and their data are untouched."
          onClose={() => setConfirmPurge(false)} onConfirm={purge} />
      )}
    </div>
  );
}

function WsModal({ ws, onClose, onSaved, toast }) {
  const [name, setName] = useState(ws?.name || '');
  const [description, setDescription] = useState(ws?.description || '');
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      if (ws) await api.patch(`/workspaces/${ws.id}`, { name, description });
      else await api.post('/workspaces', { name, description });
      onSaved();
    } catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };
  return (
    <Modal title={ws ? 'Rename workspace' : 'New workspace'} onClose={onClose} footer={
      <><button className="btn ghost" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!name.trim() || busy} onClick={save}>{busy ? <span className="spinner" /> : ws ? 'Save' : 'Create'}</button></>
    }>
      <div className="field"><label className="lbl">Name</label><input className="input" value={name} onChange={e => setName(e.target.value)} autoFocus /></div>
      <div className="field"><label className="lbl">Description</label><textarea className="input" rows={3} value={description} onChange={e => setDescription(e.target.value)} /></div>
    </Modal>
  );
}
