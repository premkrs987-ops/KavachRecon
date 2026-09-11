import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';

/* ---------- toasts ---------- */
const ToastCtx = createContext(null);
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const push = useCallback((msg, kind = 'ok') => {
    const id = Math.random().toString(36).slice(2);
    setToasts(t => [...t, { id, msg, kind }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4200);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts">
        {toasts.map(t => <div key={t.id} className={`toast ${t.kind === 'err' ? 'err' : t.kind === 'warn' ? 'warn' : ''}`}>{t.msg}</div>)}
      </div>
    </ToastCtx.Provider>
  );
}
export const useToast = () => useContext(ToastCtx);

/* ---------- badges ---------- */
const SEV = { CRITICAL: ['b-red', 'CRIT'], HIGH: ['b-red', 'HIGH'], MEDIUM: ['b-orange', 'MED'], LOW: ['b-blue', 'LOW'], INFO: ['b-gray', 'INFO'] };
export const SevBadge = ({ sev }) => { const [cls, label] = SEV[sev] || SEV.INFO; return <span className={`badge ${cls}`}>{label}</span>; };

const CLS = {
  CONFIRMED_FINDING: 'b-red', VERIFIED: 'b-orange', OBSERVED: 'b-blue', INFERRED: 'b-purple',
  HEURISTIC: 'b-gold', MANUAL_REVIEW: 'b-teal',
};
const CLS_LABEL = { CONFIRMED_FINDING: 'CONFIRMED', MANUAL_REVIEW: 'MANUAL REVIEW' };
export const ClassBadge = ({ c }) => <span className={`badge ${CLS[c] || 'b-gray'}`} title={`Classification: ${c}`}>{CLS_LABEL[c] || c}</span>;

const MODST = {
  COMPLETED: ['b-green', 'COMPLETED'], COMPLETED_NO_RESULTS: ['b-gray', 'NO RESULTS'], FAILED: ['b-red', 'FAILED'],
  SKIPPED: ['b-gold', 'SKIPPED'], NOT_APPLICABLE: ['b-gray', 'N/A'], QUEUED: ['b-blue', 'QUEUED'], RUNNING: ['b-teal', 'RUNNING'],
};
export const ModStatus = ({ s }) => { const [cls, label] = MODST[s] || MODST.QUEUED; return <span className={`badge ${cls}`}>{s === 'RUNNING' && <span className="dot" style={{ animation: 'spin 2s linear infinite' }} />}{label}</span>; };

export const ScanStatus = ({ s }) => {
  const map = { QUEUED: 'b-blue', RUNNING: 'b-teal', COMPLETED: 'b-green', COMPLETED_WITH_FAILURES: 'b-gold', FAILED: 'b-red', CANCELLED: 'b-gray' };
  return <span className={`badge ${map[s] || 'b-gray'}`}>{s === 'RUNNING' && <span className="dot" />}{s?.replace(/_/g, ' ')}</span>;
};

export const DemoBadge = ({ demo }) => (demo ? <span className="badge b-demo">DEMO DATA</span> : null);

export const ModeBadge = ({ m }) => (
  <span className={`badge ${m === 'ACTIVE_CONFIRMED' ? 'b-orange' : 'b-teal'}`}>{m === 'ACTIVE_CONFIRMED' ? 'ACTIVE' : 'PASSIVE'}</span>
);

/* ---------- empty / loading ---------- */
export const Empty = ({ icon = '🛰️', title, hint, action }) => (
  <div className="empty">
    <div className="icon">{icon}</div>
    <h4>{title}</h4>
    {hint && <p>{hint}</p>}
    {action}
  </div>
);
export const Skeleton = ({ h = 14, w = '100%', style = {} }) => <div className="skel" style={{ height: h, width: w, ...style }} />;
export const Loading = ({ label = 'Loading…' }) => (
  <div className="row" style={{ justifyContent: 'center', padding: 40, color: 'var(--faint)' }}>
    <span className="spinner" /> <span>{label}</span>
  </div>
);

/* ---------- modal & drawer ---------- */
export function Modal({ title, onClose, children, footer, wide }) {
  useEffect(() => {
    const h = (e) => e.key === 'Escape' && onClose?.();
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className={`modal ${wide ? 'wide' : ''}`}>
        <header>{title}<button className="x" onClick={onClose} aria-label="Close">✕</button></header>
        <div className="body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </div>
  );
}
export function Drawer({ title, subtitle, onClose, children }) {
  return (
    <>
      <div className="drawer-overlay" onMouseDown={onClose} />
      <div className="drawer">
        <div className="dhead">
          <div className="row">
            <div className="grow">
              <div style={{ fontWeight: 700, fontSize: 15 }}>{title}</div>
              {subtitle && <div className="muted small mono" style={{ wordBreak: 'break-all' }}>{subtitle}</div>}
            </div>
            <button className="btn sm ghost" onClick={onClose}>✕</button>
          </div>
        </div>
        <div className="dbody">{children}</div>
      </div>
    </>
  );
}

/* ---------- confirm ---------- */
export const Confirm = ({ title, message, confirmLabel = 'Confirm', danger, onConfirm, onClose, busy }) => (
  <Modal title={title} onClose={onClose} footer={
    <>
      <button className="btn ghost" onClick={onClose}>Cancel</button>
      <button className={`btn ${danger ? 'danger' : 'primary'}`} disabled={busy} onClick={onConfirm}>{busy ? <span className="spinner" /> : confirmLabel}</button>
    </>
  }>
    <div style={{ fontSize: 13.5, color: 'var(--sub)', lineHeight: 1.6 }}>{message}</div>
  </Modal>
);

/* ---------- charts ---------- */
export function Donut({ data, size = 148, thickness = 15, center }) {
  const total = data.reduce((a, d) => a + d.value, 0) || 1;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let acc = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1a2b47" strokeWidth={thickness} />
      {data.map((d, i) => {
        const frac = d.value / total;
        const el = (
          <circle key={i} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={d.color} strokeWidth={thickness}
            strokeDasharray={`${frac * c} ${c}`} strokeDashoffset={-acc * c} transform={`rotate(-90 ${size / 2} ${size / 2})`} strokeLinecap="butt" />
        );
        acc += frac;
        return el;
      })}
      {center && <text x="50%" y="47%" textAnchor="middle" fill="#e6eef7" fontSize="21" fontWeight="800">{center[0]}</text>}
      {center && <text x="50%" y="61%" textAnchor="middle" fill="#64748f" fontSize="9.5" style={{ letterSpacing: 1 }}>{center[1]}</text>}
    </svg>
  );
}
export const SEV_COLORS = { CRITICAL: '#e11d48', HIGH: '#f87171', MEDIUM: '#fb923c', LOW: '#60a5fa', INFO: '#94a3b8' };
export const SEV_LABELS = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info' };

export function SevBars({ severity }) {
  const max = Math.max(1, ...Object.values(severity));
  return (
    <div style={{ display: 'grid', gap: 8 }}>
      {Object.keys(SEV_COLORS).map(s => (
        <div key={s} className="row" style={{ gap: 10 }}>
          <div style={{ width: 62, fontSize: 11, color: 'var(--sub)', fontWeight: 700 }}>{SEV_LABELS[s].toUpperCase()}</div>
          <div style={{ flex: 1, height: 9, background: '#14243d', borderRadius: 5, overflow: 'hidden' }}>
            <div style={{ width: `${(severity[s] / max) * 100}%`, height: '100%', background: SEV_COLORS[s], borderRadius: 5, transition: 'width .4s' }} />
          </div>
          <div style={{ width: 30, textAlign: 'right', fontWeight: 700, fontSize: 12.5 }}>{severity[s]}</div>
        </div>
      ))}
    </div>
  );
}

/* ---------- markdown-lite renderer (AI outputs) ---------- */
export function Markdown({ text }) {
  if (!text) return null;
  const html = text
    .replace(/[<>]/g, (c) => ({ '<': '&lt;', '>': '&gt;' }[c]))
    .replace(/^### (.*)$/gm, '<h3>$1</h3>')
    .replace(/^## (.*)$/gm, '<h2>$1</h2>')
    .replace(/^# (.*)$/gm, '<h2>$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code style="font-family:var(--mono);font-size:12px;color:var(--accent)">$1</code>')
    .replace(/^\s*[-*] (.*)$/gm, '<li>$1</li>')
    .replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>')
    .split(/\n{2,}/).map(p => (/^<(h2|h3|ul)/.test(p.trim()) ? p : `<p>${p.replace(/\n/g, '<br/>')}</p>`)).join('');
  return <div className="markdown" dangerouslySetInnerHTML={{ __html: html }} />;
}

/* ---------- polling hook ---------- */
export function usePoll(fn, ms, active = true) {
  const ref = useRef(fn); ref.current = fn;
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => ref.current?.(), ms);
    return () => clearInterval(id);
  }, [ms, active]);
}
