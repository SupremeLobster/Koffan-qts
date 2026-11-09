// The logout result is a standalone page, without the shopping app or its
// offline store open. Never navigate away automatically and silently log in.
(async () => {
    try {
        localStorage.removeItem('koffan-owner');
    } catch (_) {}
    try {
        indexedDB.deleteDatabase('koffan-offline');
    } catch (_) {}
    try {
        if ('caches' in window) {
            const keys = await caches.keys();
            await Promise.all(keys.filter(key => key.startsWith('koffan-')).map(key => caches.delete(key)));
        }
    } catch (_) {}
})();
