// Wait for authenticated QTS-origin cleanup before opening the login iframe.
(async () => {
    const t = window.qnapTranslate;
    const token = document.body.dataset.logoutToken;
    const frame = document.getElementById('qts-logout-helper');
    function showProblem(message) {
        document.getElementById('logout-status').textContent = message;
        document.getElementById('logout-problem').hidden = false;
    }
    async function clearOfflineData() {
        try { localStorage.removeItem('koffan-owner'); } catch (_) {}
        const jobs = [new Promise(resolve => {
            try {
                const request = indexedDB.deleteDatabase('koffan-offline');
                request.onsuccess = request.onerror = request.onblocked = resolve;
            } catch (_) { resolve(); }
        }), (async () => {
            try {
                if ('caches' in window) {
                    const keys = await caches.keys();
                    await Promise.all(keys.filter(key => key.startsWith('koffan-')).map(key => caches.delete(key)));
                }
            } catch (_) {}
        })()];
        let timeout;
        await Promise.race([Promise.all(jobs), new Promise(resolve => { timeout = setTimeout(resolve, 2000); })]);
        clearTimeout(timeout);
    }
    const offlineCleanup = clearOfflineData();
    try {
        if (document.body.dataset.expired === 'true') throw new Error('expired');
        const helper = new URL(document.body.dataset.helperUrl);
        if (!['http:', 'https:'].includes(helper.protocol) || !/^[a-f0-9]{64}$/.test(token)) throw new Error('configuration');
        await new Promise((resolve, reject) => {
            let finished = false;
            const timer = setTimeout(() => finish(new Error('timeout')), 35000);
            function finish(error) {
                if (finished) return;
                finished = true;
                clearTimeout(timer);
                window.removeEventListener('message', receive);
                frame.removeEventListener('load', send);
                frame.removeEventListener('error', failed);
                if (error) reject(error); else resolve();
            }
            function receive(event) {
                const data = event.data;
                if (event.origin !== helper.origin || event.source !== frame.contentWindow ||
                    !data || data.type !== 'qts.logout.result' || data.id !== token) return;
                if (data.ok === true && data.browserCredentialsCleared === true && data.logoutRequestAccepted === true) finish();
                else finish(new Error('helper_failed'));
            }
            function send() {
                frame.contentWindow.postMessage({ type: 'qts.logout', id: token }, helper.origin);
            }
            function failed() { finish(new Error('load_failed')); }
            window.addEventListener('message', receive);
            frame.addEventListener('load', send);
            frame.addEventListener('error', failed);
            frame.src = helper.href;
        });
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 20000);
        let response;
        try {
            response = await fetch('/auth/qts/logout/complete', {
                method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
                signal: controller.signal, headers: { 'X-QTS-Logout-Token': token, Accept: 'application/json' }
            });
            if (!response.ok || (await response.json()).logged_out !== true) throw new Error('verification');
        } finally { clearTimeout(timeout); }
        await offlineCleanup;
        window.location.replace('/');
    } catch (error) {
        if (error.message === 'expired') {
            showProblem(t('logout_expired'));
        } else {
            showProblem(t('logout_unconfirmed'));
        }
    }
})();
