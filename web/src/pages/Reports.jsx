import React, { useCallback, useEffect, useState } from 'react';
import { useApp } from '../App.jsx';
import { api, fmtDT } from '../lib/api.js';
import { useToast, Empty, Loading, ScanStatus, ModeBadge, DemoBadge, SevBadge, usePoll } from '../lib/ui.jsx';

export default function Reports() {
  const { wsId } = useApp();
  const toast = useToast();
  const [scans, setScans] = useState(null);
  const [busy, setBusy] = useState(null);

  const load = useCallback(() => {
    if (!wsId) return;
    api.get(`/scans?workspace_id=${wsId}`).then(setScans).catch(e => toast(e.message, 'err'));
  }, [wsId]);
  useEffect(() => { setScans(null); load(); }, [load]);
  usePoll(load, 6000);

  const done = (s) => ['COMPLETED', 'COMPLETED_WITH_FAILURES', 'CANCELLED', 'FAILED'].includes(s.status) || s.id === 'ws';

  const dl = (s, path, label) => {
    setBusy(s.id + label);
    try { api.download(path); toast(`${label} export requested`); } finally { setTimeout(() => setBusy(null), 700); }
  };

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="callout">
        Every export is generated from the live database — the same rows the dashboard shows. The PDF includes all 19 sections: cover, executive summary, scope, methodology, module matrix, inventories (asset/DNS/network/web/endpoints/JS/tech/posture), findings, manual-review items, comparison, limitations and the evidence appendix. Failed modules are declared — never hidden.
      </div>
      <div className="card row wrap">
        <div style={{ fontSize: 22 }}>🗃️</div>
        <div className="grow" style={{ minWidth: 220 }}>
          <div style={{ fontWeight: 700 }}>Workspace asset inventory (CSV)</div>
          <div className="muted small">Every de-duplicated asset in this workspace — across all scans — with origin, confidence, verification and first/last seen.</div>
        </div>
        <button className="btn" onClick={() => dl({ id: 'ws' }, `/workspaces/${wsId}/export/assets.csv`, 'Workspace CSV')}>Download</button>
      </div>
      {!scans ? <Loading /> : scans.length === 0 ? (
        <div className="card"><Empty icon="📄" title="Nothing to report yet" hint="Complete a scan to unlock professional PDF reporting and structured exports." /></div>
      ) : scans.map(s => {
        const t = s.summary?.totals || {};
        return (
          <div key={s.id} className="card">
            <div className="row wrap" style={{ gap: 8 }}>
              <div className="grow" style={{ minWidth: 240 }}>
                <div className="row wrap" style={{ gap: 8 }}>
                  <b style={{ fontSize: 15 }}>{s.name}</b>
                  <ScanStatus s={s.status} /><ModeBadge m={s.mode} /><DemoBadge demo={s.is_demo} />
                </div>
                <div className="muted small mono" style={{ marginTop: 3 }}>
                  {s.target_identifier} · {fmtDT(s.finished_at || s.created_at)} · {t.assets ?? 0} assets · {t.findings ?? 0} findings · {t.evidence ?? 0} evidence records
                  {s.summary?.failed_modules ? ` · ⚠ ${s.summary.failed_modules} failed modules` : ''}
                </div>
              </div>
              <div className="row wrap" style={{ gap: 6 }}>
                <button className="btn primary" disabled={!done(s) || busy === s.id + 'pdf'} onClick={() => dl(s, `/scans/${s.id}/export/pdf`, 'PDF')}>
                  {busy === s.id + 'pdf' ? <span className="spinner" /> : '📄'} PDF report
                </button>
                <button className="btn" disabled={!done(s)} onClick={() => dl(s, `/scans/${s.id}/export/assets.csv`, 'Assets CSV')}>📊 Assets CSV</button>
                <button className="btn" disabled={!done(s)} onClick={() => dl(s, `/scans/${s.id}/export/findings.csv`, 'Findings CSV')}>⚠️ Findings CSV</button>
                <button className="btn" disabled={!done(s)} onClick={() => dl(s, `/scans/${s.id}/export/json`, 'JSON')}>🧾 JSON</button>
                <button className="btn" disabled={!done(s)} onClick={() => dl(s, `/scans/${s.id}/export/evidence.zip`, 'Evidence ZIP')}>🔒 Evidence</button>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
