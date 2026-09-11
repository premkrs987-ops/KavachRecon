const base = '/api';
const TOKEN_KEY = 'kr_token';

export const getToken = () => localStorage.getItem(TOKEN_KEY) || '';
export const setToken = (t) => { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY); };

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
    setToken('');
    window.dispatchEvent(new CustomEvent('kr:unauthorized'));
    throw new Error('Session expired — sign in again.');
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
  post: (p, body = {}) => req(p, { method: 'POST', body }),
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
