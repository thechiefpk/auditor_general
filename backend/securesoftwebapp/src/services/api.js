// Prefer HTTPS to avoid redirect that breaks CORS preflight
const DEFAULT_API_BASE = 'https://localhost:7120/api';
const FALLBACK_API_BASE = 'http://localhost:5059/api';

// Allow overriding via global or env-like variable if present
const API_BASE = (typeof window !== 'undefined' && window.__API_BASE__) || DEFAULT_API_BASE;

let refreshPromise = null; // Promise for in-flight refresh to avoid concurrent refreshes

async function doRefresh(refreshToken) {
    if (!refreshToken) throw new Error('No refresh token');
    // Call refresh endpoint directly (no Authorization header)
    const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
    });
    if (!res.ok) throw new Error('Refresh failed');
    const data = await res.json();
    if (data?.token) {
        localStorage.setItem('authToken', data.token);
        if (data?.refresh) localStorage.setItem('refreshToken', data.refresh);
        return data;
    }
    throw new Error('Invalid refresh response');
}

async function request(url, options = {}, opts = {}) {
    const { timeout = 10000, retries = 1 } = opts;
    let attempt = 0;

    // attach auth token if present
    const token = typeof window !== 'undefined' ? localStorage.getItem('authToken') : null;
    const headers = { ...(options.headers || {}) };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    while (true) {
        attempt++;
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        try {
            const res = await fetch(url, { ...options, headers, signal: controller.signal });
            clearTimeout(id);

            const text = await res.text();
            let parsed;
            try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }

            if (res.status === 401) {
                // try refresh flow once
                const refreshToken = localStorage.getItem('refreshToken');
                try {
                    if (!refreshPromise) refreshPromise = doRefresh(refreshToken).finally(() => { refreshPromise = null; });
                    await refreshPromise;
                    // update Authorization header with new token and retry request once
                    const newToken = localStorage.getItem('authToken');
                    if (newToken) headers['Authorization'] = `Bearer ${newToken}`;
                    const retryRes = await fetch(url, { ...options, headers });
                    const retryText = await retryRes.text();
                    let retryParsed;
                    try { retryParsed = retryText ? JSON.parse(retryText) : null; } catch { retryParsed = retryText; }
                    if (!retryRes.ok) {
                        const errMsg = retryParsed && typeof retryParsed === 'object' ? (retryParsed.error || retryParsed.message || JSON.stringify(retryParsed)) : (retryParsed || retryRes.statusText);
                        throw new Error(typeof errMsg === 'string' ? errMsg : JSON.stringify(errMsg));
                    }
                    return retryParsed;
                } catch (refreshError) {
                    // couldn't refresh, clear tokens and surface401
                    localStorage.removeItem('authToken');
                    localStorage.removeItem('refreshToken');
                    // notify UI to handle logout/redirect
                    try { window.dispatchEvent(new Event('logout')); } catch { }
                    const err = parsed && typeof parsed === 'object' ? (parsed.error || parsed.message || JSON.stringify(parsed)) : (parsed || res.statusText);
                    throw new Error(typeof err === 'string' ? err : JSON.stringify(err));
                }
            }

            if (!res.ok) {
                const errMsg = parsed && typeof parsed === 'object' ? (parsed.error || parsed.message || JSON.stringify(parsed)) : (parsed || res.statusText);
                throw new Error(typeof errMsg === 'string' ? errMsg : JSON.stringify(errMsg));
            }

            return parsed;
        } catch (err) {
            clearTimeout(id);
            const isAbort = err.name === 'AbortError';
            const isNetwork = err instanceof TypeError && err.message === 'Failed to fetch';

            if ((isAbort || isNetwork || /network/i.test(err.message) || /timeout/i.test(err.message)) && attempt <= retries) {
                // small backoff
                await new Promise(r => setTimeout(r, 300 * attempt));
                continue;
            }

            throw err;
        }
    }
}

export default {
    // scan endpoints (backend expects JSON { path })
    scanJson: (body) => request(`${API_BASE}/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }, { timeout: 30000, retries: 2 }),
    scanText: (text) => request(`${API_BASE}/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: text }) }, { timeout: 30000, retries: 2 }),

    getStats: (id) => request(`${API_BASE}/stats/${id}`, { method: 'GET' }, { timeout: 15000, retries: 1 }),
    getReport: (id) => request(`${API_BASE}/report/${id}`, { method: 'GET' }, { timeout: 15000, retries: 1 }),
    getReportViolations: (id, page = 1, pageSize = 25, category = null, q = null, sortBy = 'filePath', sortDir = 'asc') => {
        const params = new URLSearchParams();
        params.set('page', String(page));
        params.set('pageSize', String(pageSize));
        if (category) params.set('category', category);
        if (q) params.set('q', q);
        if (sortBy) params.set('sortBy', sortBy);
        if (sortDir) params.set('sortDir', sortDir);
        const url = `${API_BASE}/report/${id}/violations?${params.toString()}`;
        return request(url, { method: 'GET' }, { timeout: 15000, retries: 1 });
    },
    getTopFiles: (id, limit = 10) => request(`${API_BASE}/stats/${id}/topfiles?limit=${limit}`, { method: 'GET' }, { timeout: 15000, retries: 1 }),

    // auth
    login: (username, password) => request(`${API_BASE}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) }, { timeout: 10000 }),
    register: (username, email, password) => request(`${API_BASE}/auth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, email, password }) }, { timeout: 10000 }),
    refresh: (refreshToken) => request(`${API_BASE}/auth/refresh`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refreshToken }) }, { timeout: 10000 }),
    revoke: (refreshToken) => request(`${API_BASE}/auth/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refreshToken }) }, { timeout: 10000 }),
};
