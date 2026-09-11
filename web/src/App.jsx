import React, { createContext, useContext, useEffect, useState } from 'react';
import { Routes, Route, NavLink, Link, useLocation, useNavigate, Navigate } from 'react-router-dom';
import { api, setToken } from './lib/api.js';
import { ToastProvider, useToast, Loading, Modal } from './lib/ui.jsx';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Targets from './pages/Targets.jsx';
import Scans from './pages/Scans.jsx';
import ScanDetail from './pages/ScanDetail.jsx';
import Assets from './pages/Assets.jsx';
import FindingsPage from './pages/Findings.jsx';
import GraphPage from './pages/Graph.jsx';
import Reports from './pages/Reports.jsx';
import AIAssistant from './pages/AIAssistant.jsx';
import Audit from './pages/Audit.jsx';
import Settings from './pages/Settings.jsx';

const AppCtx = createContext(null);
export const useApp = () => useContext(AppCtx);

const Icon = ({ d }) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
);
const NAV = [
  { sec: 'Operate' },
  { to: '/', label: 'Dashboard', icon: 'M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z' },
  { to: '/targets', label: 'Targets & Scope', icon: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10zM12 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2z' },
  { to: '/scans', label: 'Scans', icon: 'M4 20h16M6 20V10m6 10V4m6 16v-7' },
  { sec: 'Intelligence' },
  { to: '/assets', label: 'Asset Inventory', icon: 'M4 6h16M4 12h16M4 18h10' },
  { to: '/findings', label: 'Findings', icon: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z' },
  { to: '/graph', label: 'Attack-Surface Graph', icon: 'M6 3v12m12-9v12M6 9a3 3 0 1 0 0 0m12 6a3 3 0 1 0 0 0M6 9h12M6 15h0' },
  { to: '/ai', label: 'AI Assistant', icon: 'M12 2l2.4 5.4L20 9l-4.2 3.9L17 19l-5-2.8L7 19l1.2-6.1L4 9l5.6-1.6z' },
  { sec: 'Output' },
  { to: '/reports', label: 'Reports & Exports', icon: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5' },
  { sec: 'Governance' },
  { to: '/audit', label: 'Audit Trail', icon: 'M12 8v4l3 3m6-3a9 9 0 1 1-18 0 9 9 0 0 1 18 0z' },
  { to: '/settings', label: 'Settings', icon: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z' },
];

function Shell({ children }) {
  const { user, workspaces, wsId, setWsId } = useApp();
  const loc = useLocation();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [loc.pathname]);
  const ws = workspaces.find(w => w.id === wsId);
  const title = NAV.find(n => n.to === loc.pathname)?.label || (loc.pathname.startsWith('/scans/') ? 'Scan Detail' : 'KavachRecon');
  return (
    <div className="shell">
      <aside className={`sidebar ${open ? 'open' : ''}`}>
        <div className="logo">
          <svg width="30" height="30" viewBox="0 0 24 24"><path fill="#0e9384" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" /><path fill="#0b1220" d="M11 14.8l-2.8-2.8 1.4-1.4 1.4 1.4 4-4 1.4 1.4z" /></svg>
          <div><div className="name">Kavach<b>Recon</b></div><div className="tag">Recon Intelligence</div></div>
        </div>
        {NAV.map(n => n.sec
          ? <div key={n.sec} className="navsec">{n.sec}</div>
          : <NavLink key={n.to} to={n.to} end={n.to === '/'} className={({ isActive }) => `nav ${isActive ? 'active' : ''}`}><Icon d={n.icon} />{n.label}</NavLink>)}
        <div className="sidefoot">KavachRecon Intelligence Platform<br /><b>Built by @premkrs</b></div>
      </aside>
      <div className="main">
        <div className="topbar">
          <button className="btn sm ghost menu-btn" onClick={() => setOpen(o => !o)}>☰</button>
          <h1>{title}</h1>
          <span className="crumb">/ {ws?.name}</span>
          <div className="spacer" />
          {ws?.is_demo === 1 && <span className="badge b-demo">DEMO WORKSPACE</span>}
          <select className="wsselect" value={wsId || ''} onChange={e => setWsId(e.target.value)}>
            {workspaces.map(w => <option key={w.id} value={w.id}>{w.name}{w.is_demo ? ' (demo)' : ''}</option>)}
          </select>
          <div className="avatar" title={user?.name}>{(user?.name || '?').split(' ').map(x => x[0]).slice(0, 2).join('')}</div>
        </div>
        <div className="content">{children}</div>
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [booting, setBooting] = useState(true);
  const [workspaces, setWorkspaces] = useState([]);
  const [wsId, setWsIdState] = useState(localStorage.getItem('kr_ws') || null);
  const nav = useNavigate();

  const refreshWorkspaces = async () => {
    const ws = await api.get('/workspaces');
    setWorkspaces(ws);
    setWsIdState(cur => (ws.find(w => w.id === cur) ? cur : ws[0]?.id || null));
    return ws;
  };
  const setWsId = (id) => { setWsIdState(id); localStorage.setItem('kr_ws', id || ''); };

  const doLogin = async (u) => {
    setUser(u);
    try { await refreshWorkspaces(); } catch { /* workspace errors must not block entry */ }
    nav('/', { replace: true });
  };

  useEffect(() => {
    api.get('/auth/me')
      .then(r => { if (r.user) doLogin(r.user); else setBooting(false); })
      .catch(() => setBooting(false));
    let checking = false;
    const on401 = async () => {
      if (checking) return;
      checking = true;
      try {
        const me = await api.get('/auth/me');
        if (me.user) return; // session is actually alive — transient 401, ignore
      } catch { /* truly unauthenticated */ } finally { checking = false; }
      setToken('');
      setUser(null);
      nav('/login');
    };
    window.addEventListener('kr:unauthorized', on401);
    return () => window.removeEventListener('kr:unauthorized', on401);
  }, []);

  if (booting) return <Loading label="Starting KavachRecon…" />;
  if (!user) return <Login onLogin={doLogin} />;

  return (
    <AppCtx.Provider value={{ user, workspaces, wsId, setWsId, refreshWorkspaces }}>
      <Routes>
        <Route path="/login" element={<Navigate to="/" replace />} />
        <Route path="*" element={<Shell>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/graph" element={<GraphPage />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/ai" element={<AIAssistant />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </Shell>} />
      </Routes>
    </AppCtx.Provider>
  );
}
