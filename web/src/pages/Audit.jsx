import React, { useCallback, useEffect, useState } from 'react';
import { api, fmtDT } from '../lib/api.js';
import { useToast, Loading, Empty, usePoll } from '../lib/ui.jsx';

const ACTION_COLOR = (a) => {
  if (a.includes('delete') || a.includes('purge')) return 'b-red';
  if (a.includes('create') || a.includes('start')) return 'b-green';
  if (a.includes('login')) return 'b-blue';
  if (a.includes('export')) return 'b-purple';
  if (a.includes('cancel')) return 'b-gold';
  return 'b-gray';
};

export default function Audit() {
  const [rows, setRows] = useState(null);
  const toast = useToast();
  const load = useCallback(() => api.get('/audit?limit=200').then(setRows).catch(e => toast(e.message, 'err')), []);
  useEffect(() => { load(); }, [load]);
  usePoll(load, 6000);
  if (!rows) return <Loading />;
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="callout">Complete audit trail: authentication, target/scope changes, scan lifecycle, cancellations, finding decisions, exports and AI usage — with actor and timestamps.</div>
      <div className="card pad0">
        {rows.length === 0 ? <Empty icon="📜" title="No audit entries yet" />
          : <div className="tblwrap"><table className="tbl">
            <thead><tr><th>When (UTC)</th><th>Actor</th><th>Action</th><th>Entity</th><th>Detail</th></tr></thead>
            <tbody>{rows.map(r => (
              <tr key={r.id}>
                <td className="mono dim small">{String(r.ts).replace('T', ' ').slice(0, 19)}</td>
                <td style={{ fontWeight: 600 }}>{r.actor}</td>
                <td><span className={`badge ${ACTION_COLOR(r.action)}`}>{r.action}</span></td>
                <td className="mono small dim">{r.entity}{r.entity_id ? `#${String(r.entity_id).slice(-6)}` : ''}</td>
                <td className="mono small dim" style={{ maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.detail !== '{}' ? r.detail.slice(0, 120) : '—'}</td>
              </tr>
            ))}</tbody>
          </table></div>}
      </div>
    </div>
  );
}
