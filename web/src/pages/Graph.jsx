import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useApp } from '../App.jsx';
import { api } from '../lib/api.js';
import { useToast, Loading, Empty, Drawer, usePoll } from '../lib/ui.jsx';
import { EvidenceCard } from './ScanDetail.jsx';

const TYPE_STYLE = {
  DOMAIN: { color: '#a78bfa', r: 11 }, SUBDOMAIN: { color: '#2dd4bf', r: 8 }, IP: { color: '#60a5fa', r: 8 },
  HOST: { color: '#38bdf8', r: 7 }, CIDR: { color: '#64748b', r: 8 }, PORT: { color: '#fb923c', r: 5.5 },
  SERVICE: { color: '#f87171', r: 5 }, URL: { color: '#94a3b8', r: 5 }, ENDPOINT: { color: '#fbbf24', r: 5 },
  TECHNOLOGY: { color: '#34d399', r: 6 }, CERT: { color: '#c084fc', r: 6 }, JS_RESOURCE: { color: '#5eead4', r: 5.5 }, CLOUD: { color: '#7dd3fc', r: 6 },
};

export default function GraphPage() {
  const { wsId } = useApp();
  const toast = useToast();
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState('');
  const [graph, setGraph] = useState(null);
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [typeFilter, setTypeFilter] = useState(new Set());

  useEffect(() => { api.get(`/scans?workspace_id=${wsId}`).then(s => setScans(s.filter(x => ['COMPLETED', 'COMPLETED_WITH_FAILURES'].includes(x.status)))).catch(() => setScans([])); }, [wsId]);
  useEffect(() => {
    setGraph(null);
    const p = scanId ? `scan_id=${scanId}` : `workspace_id=${wsId}`;
    api.get(`/graph?${p}`).then(setGraph).catch(e => toast(e.message, 'err'));
  }, [wsId, scanId]);

  const types = useMemo(() => [...new Set((graph?.nodes || []).map(n => n.type))], [graph]);
  const nodes = useMemo(() => (graph?.nodes || []).filter(n => typeFilter.size === 0 || typeFilter.has(n.type)), [graph, typeFilter]);
  const nodeIds = useMemo(() => new Set(nodes.map(n => n.id)), [nodes]);
  const edges = useMemo(() => (graph?.edges || []).filter(e => nodeIds.has(e.src_id) && nodeIds.has(e.dst_id)), [graph, nodeIds]);

  const openNode = async (n) => { setSel(n); setDetail(await api.get(`/assets/${n.id}`)); };

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="row wrap">
        <select className="input" style={{ maxWidth: 320 }} value={scanId} onChange={e => setScanId(e.target.value)}>
          <option value="">Whole workspace</option>
          {scans.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
        <div className="spacer" />
        <div className="row wrap" style={{ gap: 5 }}>
          {types.map(t => {
            const on = typeFilter.size === 0 || typeFilter.has(t);
            return (
              <button key={t} className="btn sm ghost" style={{ opacity: on ? 1 : .4, borderColor: on ? TYPE_STYLE[t]?.color : undefined }}
                onClick={() => setTypeFilter(prev => {
                  const n = new Set(prev.size === 0 ? types : prev);
                  if (n.has(t)) n.delete(t); else n.add(t);
                  return n;
                })}>
                <span className="gdot" style={{ background: TYPE_STYLE[t]?.color }} /> {t.toLowerCase()}
              </button>
            );
          })}
        </div>
      </div>
      {!graph ? <Loading label="Building graph…" />
        : nodes.length === 0 ? <div className="card"><Empty icon="🕸️" title="No graph data" hint="The attack-surface graph (Domain → Subdomain → IP → Port → Service → URL → Endpoint → Technology) is built from discovered asset relationships. Run a scan to populate it." /></div>
          : <ForceGraph nodes={nodes} edges={edges} onSelect={openNode} selId={sel?.id} />}
      {sel && detail && (
        <Drawer title={<span className="mono" style={{ wordBreak: 'break-all' }}>{detail.key}</span>} subtitle={detail.type} onClose={() => setSel(null)}>
          <div className="kv" style={{ marginBottom: 12 }}>
            <div className="k">Status</div><div>{detail.status}</div>
            <div className="k">Confidence</div><div>{detail.confidence}</div>
            <div className="k">First / last seen</div><div className="small">{new Date(detail.first_seen).toLocaleString()} → {new Date(detail.last_seen).toLocaleString()}</div>
          </div>
          <div className="row wrap" style={{ gap: 5, marginBottom: 14 }}>
            {detail.edges_out.map(e => <span key={e.id} className="badge b-gray">{e.relation} → <span className="mono">{String(e.key).slice(0, 40)}</span></span>)}
            {detail.edges_in.map(e => <span key={e.id} className="badge b-gray">← {e.relation} · <span className="mono">{String(e.key).slice(0, 40)}</span></span>)}
          </div>
          <label className="lbl">Evidence ({detail.evidence.length})</label>
          {detail.evidence.slice(0, 10).map(ev => <EvidenceCard key={ev.id} ev={ev} />)}
        </Drawer>
      )}
    </div>
  );
}

function ForceGraph({ nodes, edges, onSelect, selId }) {
  const wrapRef = useRef(null);
  const simRef = useRef(null);
  const [, setTick] = useState(0);

  useEffect(() => {
    // simple force-directed simulation
    const W = wrapRef.current?.clientWidth || 900, H = wrapRef.current?.clientHeight || 620;
    const ns = nodes.map(n => ({ ...n, x: W / 2 + (Math.random() - .5) * 300, y: H / 2 + (Math.random() - .5) * 300, vx: 0, vy: 0 }));
    const idx = new Map(ns.map(n => [n.id, n]));
    const es = edges.map(e => ({ s: idx.get(e.src_id), t: idx.get(e.dst_id), rel: e.relation })).filter(e => e.s && e.t);
    let alpha = 1;
    let raf;
    const step = () => {
      alpha *= 0.995;
      // repulsion (sparse grid approximation for perf)
      for (let i = 0; i < ns.length; i++) {
        const a = ns[i];
        for (let j = i + 1; j < ns.length; j++) {
          const b = ns[j];
          let dx = b.x - a.x, dy = b.y - a.y;
          let d2 = dx * dx + dy * dy + 0.01;
          const rep = (a.type === b.type ? 900 : 1600) / d2;
          const d = Math.sqrt(d2);
          dx /= d; dy /= d;
          a.vx -= dx * rep; a.vy -= dy * rep;
          b.vx += dx * rep; b.vy += dy * rep;
        }
      }
      // springs
      for (const e of es) {
        let dx = e.t.x - e.s.x, dy = e.t.y - e.s.y;
        const d = Math.sqrt(dx * dx + dy * dy) + 0.01;
        const want = 78;
        const f = (d - want) * 0.015;
        dx /= d; dy /= d;
        e.s.vx += dx * f; e.s.vy += dy * f;
        e.t.vx -= dx * f; e.t.vy -= dy * f;
      }
      // centering + integrate
      for (const n of ns) {
        n.vx += (W / 2 - n.x) * 0.0025; n.vy += (H / 2 - n.y) * 0.0025;
        n.vx *= 0.86; n.vy *= 0.86;
        n.x = Math.max(20, Math.min(W - 20, n.x + n.vx * Math.min(alpha, 1)));
        n.y = Math.max(20, Math.min(H - 20, n.y + n.vy * Math.min(alpha, 1)));
      }
      setTick(t => t + 1);
      if (alpha > 0.02) raf = requestAnimationFrame(step);
    };
    step();
    simRef.current = () => cancelAnimationFrame(raf);
    return () => cancelAnimationFrame(raf);
  }, [nodes, edges]);

  const ns = nodes;
  const idx = new Map(ns.map(n => [n.id, n]));
  return (
    <div className="graph-wrap" ref={wrapRef}>
      <svg>
        {edges.map((e, i) => {
          const s = idx.get(e.src_id), t = idx.get(e.dst_id);
          if (!s || !t) return null;
          return <line key={i} className="gedge" x1={s.x} y1={s.y} x2={t.x} y2={t.y} />;
        })}
        {ns.map(n => {
          const st = TYPE_STYLE[n.type] || { color: '#94a3b8', r: 5 };
          const label = String(n.key).length > 26 ? String(n.key).slice(0, 24) + '…' : n.key;
          return (
            <g key={n.id} className={`gnode ${selId === n.id ? 'sel' : ''}`} onClick={() => onSelect(n)}>
              <circle cx={n.x} cy={n.y} r={st.r} fill={n.origin === 'DEMO_SEED' ? 'transparent' : st.color} stroke={st.color} strokeDasharray={n.origin === 'DEMO_SEED' ? '3 2' : undefined} fillOpacity={.85} />
              {n.type !== 'PORT' && n.type !== 'SERVICE' && <text x={n.x + st.r + 4} y={n.y + 3.5}>{label}</text>}
            </g>
          );
        })}
      </svg>
      <div className="glegend">
        {Object.entries(TYPE_STYLE).filter(([t]) => nodes.some(n => n.type === t)).map(([t, st]) => (
          <span key={t}><span className="gdot" style={{ background: st.color }} /> {t.toLowerCase()}</span>
        ))}
        <span className="muted">dashed = demo data · click a node for evidence</span>
      </div>
    </div>
  );
}
