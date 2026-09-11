import React, { useCallback, useEffect, useState } from 'react';
import { useApp } from '../App.jsx';
import { api, ago } from '../lib/api.js';
import { useToast, Loading, Empty, Markdown, Modal, usePoll } from '../lib/ui.jsx';

export default function AIAssistant() {
  const { wsId, workspaces } = useApp();
  const toast = useToast();
  const ws = workspaces.find(w => w.id === wsId);
  const [outputs, setOutputs] = useState(null);
  const [scans, setScans] = useState([]);
  const [busy, setBusy] = useState(false);
  const [openOutput, setOpenOutput] = useState(null);

  const load = useCallback(() => {
    if (!wsId) return;
    api.get(`/ai/outputs?workspace_id=${wsId}`).then(setOutputs).catch(() => setOutputs([]));
    api.get(`/scans?workspace_id=${wsId}`).then(s => setScans(s)).catch(() => { });
  }, [wsId]);
  useEffect(() => { setOutputs(null); load(); }, [load]);
  usePoll(load, 8000);

  const brief = async () => {
    setBusy(true);
    try {
      const r = await api.post(`/ai/workspace/${wsId}/surface`);
      if (!r.ok) toast(r.message, 'err'); else { toast('Attack-surface briefing generated'); load(); }
    } catch (e) { toast(e.message, 'err'); } finally { setBusy(false); }
  };

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="callout">
        <b>NO EVIDENCE = NO CLAIM.</b> The assistant is grounded strictly on your database: workspace assets, findings, scans, modules and observations. It labels statements as observed / verified / inferred / heuristic / manual-review and refuses to invent scan results. If Gemini is not configured or unreachable, you get an explicit error — never a fabricated answer.
      </div>
      <div className="card row wrap">
        <div className="grow">
          <div style={{ fontWeight: 700 }}>Workspace attack-surface briefing</div>
          <div className="muted small">Prioritized review list, finding posture and coverage gaps for “{ws?.name}” — generated from live counts.</div>
        </div>
        <button className="btn primary" disabled={busy} onClick={brief}>{busy ? <span className="spinner" /> : '✨'} Generate briefing</button>
      </div>

      <div className="card pad0">
        <div className="row" style={{ padding: '11px 16px', borderBottom: '1px solid var(--line)' }}>
          <h3 style={{ margin: 0 }}>Per-scan AI analysis</h3><div className="spacer" />
          <span className="muted small">Open a scan → AI tab for executive summaries and Q&amp;A grounded on that scan.</span>
        </div>
        <div className="tblwrap"><table className="tbl">
          <thead><tr><th>Scan</th><th>AI actions</th></tr></thead>
          <tbody>
            {scans.length === 0 && <tr><td colSpan={2}><div className="empty" style={{ padding: 20 }}>No scans yet.</div></td></tr>}
            {scans.slice(0, 10).map(s => (
              <tr key={s.id}>
                <td style={{ fontWeight: 600 }}>{s.name}<div className="muted small mono">{s.target_identifier}</div></td>
                <td><a href={`/scans/${s.id}`} onClick={e => { e.preventDefault(); location.assign(`/scans/${s.id}`); }} className="btn sm">Open AI tab →</a></td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>

      {!outputs ? <Loading /> : outputs.length === 0 ? (
        <Empty icon="🧠" title="No AI outputs yet" hint="Generate the workspace briefing above. Outputs are stored with their grounding context and model used." />
      ) : outputs.map(o => (
        <div key={o.id} className="card row wrap">
          <div className="grow">
            <div className="row wrap" style={{ gap: 8 }}>
              <span className={`badge ${o.status === 'OK' ? 'b-teal' : 'b-red'}`}>{o.kind.replace(/_/g, ' ')}</span>
              <span className="muted small mono">{o.model}</span><span className="muted small">{ago(o.created_at)}</span>
            </div>
            <div className="small" style={{ marginTop: 4, color: o.status === 'OK' ? 'var(--sub)' : 'var(--red)' }}>{o.status === 'OK' ? o.prompt_summary : o.error}</div>
          </div>
          {o.status === 'OK' && <button className="btn sm" onClick={() => setOpenOutput(o)}>View</button>}
        </div>
      ))}
      {openOutput && <ViewOutput id={openOutput.id} onClose={() => setOpenOutput(null)} />}
    </div>
  );
}
function ViewOutput({ id, onClose }) {
  const [out, setOut] = useState(null);
  useEffect(() => { api.get(`/ai/outputs/${id}`).then(setOut); }, [id]);
  if (!out) return <Loading />;
  return (
    <Modal wide title={<span>AI {out.kind.replace(/_/g, ' ').toLowerCase()} <span className="muted small mono">· {out.model}</span></span>} onClose={onClose}>
      <Markdown text={out.content} />
      <div className="callout" style={{ marginTop: 12, fontSize: 12 }}>AI-generated from collected data only. Generated {new Date(out.created_at).toLocaleString()}.</div>
    </Modal>
  );
}
