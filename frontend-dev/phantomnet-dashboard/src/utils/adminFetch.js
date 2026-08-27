/**
 * Authenticated fetch helper — automatically handles 401 by clearing
 * the stale token and reloading the page to show the login form.
 */
export const adminFetch = async (url, options = {}) => {
    const token = localStorage.getItem('admin_token');
    const headers = {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options.headers || {}),
    };
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
        // Token is expired / invalid — force re‑login
        localStorage.removeItem('admin_token');
        localStorage.removeItem('admin_user');
        window.location.reload();
        // Return a never-resolving promise so callers don't act on stale data
        return new Promise(() => {});
    }
    return res;
};
