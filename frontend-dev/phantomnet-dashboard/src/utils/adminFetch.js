/**
 * Authenticated fetch helper — uses HttpOnly cookies (credentials: 'include')
 * rather than extracting JWTs from browser storage (UI-01).
 * Automatically handles 401 by clearing session and redirecting.
 */
export const adminFetch = async (url, options = {}) => {
    const headers = {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
    };
    const res = await fetch(url, {
        ...options,
        credentials: 'include',
        headers,
    });
    if (res.status === 401) {
        // Session expired or invalid
        window.location.reload();
        // Return a never-resolving promise so callers don't act on stale data
        return new Promise(() => {});
    }
    return res;
};
