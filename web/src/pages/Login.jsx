import React, { useEffect, useState } from 'react';
import { api } from '../lib/api.js';

export default function Login({ onLogin }) {
  const [users, setUsers] = useState([]);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => { api.get('/auth/users').then(setUsers).catch(e => setErr(e.message)); }, []);
  const signIn = async (u) => {
    setBusy(u.id);
    try { onLogin(await api.post('/auth/login', { user_id: u.id })); }
    catch (e) { setErr(e.message); } finally { setBusy(null); }
  };

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="shield">
          <svg width="30" height="30" viewBox="0 0 24 24"><path fill="#ecfffb" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" /><path fill="#0f766e" d="M11 14.8l-2.8-2.8 1.4-1.4 1.4 1.4 4-4 1.4 1.4z" /></svg>
        </div>
        <h2>KavachRecon</h2>
        <div className="sub">Authorized reconnaissance &amp; attack-surface intelligence • no passwords needed — identify yourself to continue</div>
        {err && <div className="callout danger" style={{ marginBottom: 12 }}>{err}</div>}
        {users.map(u => (
          <button key={u.id} className="user-pick" onClick={() => signIn(u)} disabled={!!busy}>
            <div className="avatar">{u.name.split(' ').map(x => x[0]).slice(0, 2).join('')}</div>
            <div className="who"><b>{u.name}</b><span>{u.email} • {u.role}</span></div>
            <span className="arr">{busy === u.id ? <span className="spinner" /> : '→'}</span>
          </button>
        ))}
        <div style={{ textAlign: 'center', marginTop: 16, color: 'var(--faint)', fontSize: 11 }}>
          KavachRecon Intelligence Platform • Built by @premkrs<br />
          Scans run only against explicitly authorized targets.
        </div>
      </div>
    </div>
  );
}
