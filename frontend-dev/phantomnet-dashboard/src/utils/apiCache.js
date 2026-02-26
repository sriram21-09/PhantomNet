// frontend/src/utils/apiCache.js

class ApiCache {
    constructor() {
        this.cache = new Map();
    }

    set(key, data, ttl = 5000) {
        const expiry = Date.now() + ttl;
        this.cache.set(key, { data, expiry });
    }

    get(key) {
        const cached = this.cache.get(key);
        if (!cached) return null;

        if (Date.now() > cached.expiry) {
            this.cache.delete(key);
            return null;
        }

        return cached.data;
    }

    clear() {
        this.cache.clear();
    }
}

export const apiCache = new ApiCache();
