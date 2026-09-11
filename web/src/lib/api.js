const base = '/api';
const TOKEN_KEY = 'kr_token';

// Storage that survives restricted environments: falls back to in-memory
// (per tab session) when localStorage is unavailable (strict iframe privacy modes).
const mem = {};
export const store = {
  get(k) { try { return localStorage.getItem(k) ?? mem[k] ?? ''; } catch { return mem[k] ?? ''; } },
  set(k, v) { mem[k] = v; try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  del(k) { delete mem[k]; try { localStorage.removeItem(k); } catch { /* private mode */ } },
};

export const getToken = () => store.get(TOKEN_KEY);
export const setToken = (t) => { t ? store.set(TOKEN_KEY, t) : store.del(TOKEN_KEY); };

// Anti-bounce guard: within a few seconds of establishing a session, a stray 401
// (race during first data loads) must never kick the user out.
let lastAuthAt = 0;
export const markAuthenticated = () => { lastAuthAt = Date.now(); };
const recentlyAuthed = () => Date.now() - lastAuthAt < 6000;

function headers() {
  const h = { 'content-type': 'application/json' };
  const t = getToken();
  if (t) h['authorization'] = `Bearer ${t}`;
  return h;
}

async function req(path, opts = {}) {
  const res = await fetch(base + path, {
    headers: headers(),
    credentials: 'same-origin',
    ...opts,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401 && !path.startsWith('/auth')) {
    if (!recentlyAuthed()) {
      setToken('');
      window.dispatchEvent(new CustomEvent('kr:unauthorized'));
    }
    throw new Error('Session expired.');
  }
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json().catch(() => ({})) : await res.text();
  if (!res.ok) {
    const msg = typeof data === 'object' && data?.message ? data.message : (typeof data === 'string' ? data.slice(0, 300) : `Request failed (${res.status})`);
    const err = new Error(msg);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

/** Fetch-to-blob download: carries the Authorization header, works inside embedded previews. */
async function download(path) {
  const res = await fetch(base + path, { headers: headers(), credentials: 'same-origin' });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data?.message || `Download failed (${res.status})`);
  }
  const blob = await res.blob();
  const cd = res.headers.get('content-disposition') || '';
  const m = cd.match(/filename="?([^";]+)"?/i);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = m ? m[1] : 'kavachrecon-export';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

export const api = {
  get: (p) => req(p),
  post: async (p, body = {}) => {
    const r = await req(p, { method: 'POST', body });
    if (p === '/auth/login' || p === '/auth/auto') markAuthenticated();
    return r;
  },
  patch: (p, body = {}) => req(p, { method: 'PATCH', body }),
  put: (p, body = {}) => req(p, { method: 'PUT', body }),
  del: (p) => req(p, { method: 'DELETE' }),
  download,
};

export const fmtDT = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—');
export const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : '—');
export const ago = (iso) => {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};
