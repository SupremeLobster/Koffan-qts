// Complete browser cleanup before returning to the normal sign-in flow.
(async () => {
    try {
        localStorage.removeItem('koffan-owner');
    } catch (_) {}
    const cleanup = [];
    cleanup.push(new Promise(resolve => {
        try {
            const request = indexedDB.deleteDatabase('koffan-offline');
            request.onsuccess = request.onerror = request.onblocked = resolve;
        } catch (_) { resolve(); }
    }));
    cleanup.push((async () => {
        try {
            if ('caches' in window) {
                const keys = await caches.keys();
                await Promise.all(keys.filter(key => key.startsWith('koffan-')).map(key => caches.delete(key)));
            }
        } catch (_) {}
    })());
    // Storage held open by another tab must not trap this tab during logout.
    let timeout;
    await Promise.race([
        Promise.all(cleanup),
        new Promise(resolve => { timeout = setTimeout(resolve, 2000); })
    ]);
    clearTimeout(timeout);
    window.location.replace('/');
})();
