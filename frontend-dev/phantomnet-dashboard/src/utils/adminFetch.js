/**
 * Authenticated fetch helper — uses HttpOnly cookies (credentials: 'include')
 * rather than extracting JWTs from browser storage (UI-01).
 * Automatically handles 401 by clearing session and redirecting.
 * Includes 'X-Requested-With': 'XMLHttpRequest' for CSRF protection compatibility.
 */
export const adminFetch = async (url, options = {}) => {
    const headers = {
        'X-Requested-With': 'XMLHttpRequest',
        ...(options.headers || {}),
    };
    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }
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

/**
 * Safely parses response JSON body.
 * If response is HTML (e.g. 502/504 Bad Gateway from proxy) or non-JSON,
 * handles it gracefully without throwing "Unexpected token '<'..." SyntaxError.
 */
export const safeParseJson = async (res, defaultErrorMessage = 'Operation failed') => {
    let text = '';
    try {
        text = await res.text();
    } catch (e) {
        throw new Error(`Failed to read response: ${e.message}`);
    }

    let data = null;
    try {
        data = text ? JSON.parse(text) : {};
    } catch {
        if (!res.ok) {
            throw new Error(`Server returned HTTP ${res.status}: ${res.statusText || 'Gateway Error'}`);
        }
        throw new Error('Received unexpected non-JSON response from server');
    }

    if (!res.ok) {
        const errorDetail = data?.detail || data?.message || defaultErrorMessage;
        throw new Error(typeof errorDetail === 'string' ? errorDetail : JSON.stringify(errorDetail));
    }
    return data;
};
