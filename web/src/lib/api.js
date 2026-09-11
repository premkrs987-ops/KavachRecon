const base = '/api';

async function req(path, opts = {}) {
  const res = await fetch(base + path, {
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    ...opts,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401 && !path.startsWith('/auth')) {
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

export const api = {
  get: (p) => req(p),
  post: (p, body = {}) => req(p, { method: 'POST', body }),
  patch: (p, body = {}) => req(p, { method: 'PATCH', body }),
  put: (p, body = {}) => req(p, { method: 'PUT', body }),
  del: (p) => req(p, { method: 'DELETE' }),
  download: (p) => { window.open(base + p, '_blank'); },
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
