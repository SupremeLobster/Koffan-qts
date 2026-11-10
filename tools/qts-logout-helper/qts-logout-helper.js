/* QTS logout helper v1. No logout occurs merely by loading this file.
 * Based on the supplied qos-core-base.js, qos-core-login.js and qos-lib.js.
 * Install on the QTS management origin, not the separate Web Server service.
 */
(() => {
    'use strict';
    const QTS_ORIGIN = 'https://shopping.mafucat.com:9443';
    const ALLOWED_APP_ORIGINS = ['https://shopping.mafucat.com'];
    if (window.QTSLogoutHelper) return;
    let running;

    function cookie(name) {
        const item = document.cookie.split(';').map(v => v.trim()).find(v => v.startsWith(name + '='));
        if (!item) return '';
        try { return decodeURIComponent(item.slice(name.length + 1)); } catch (_) { return ''; }
    }
    function accountFromTokenLabel(label) {
        // QTS uses decodeURIComponent(ezDecode(qtoken_account)); ezDecode is Base64.
        try { return decodeURIComponent(atob(label)); } catch (_) { return ''; }
    }
    async function post(path, params) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 8000);
        try {
            const response = await fetch(path, {
                method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(params), signal: controller.signal
            });
            if (!response.ok) throw new Error('QTS request failed');
            const text = await response.text();
            if (text.length > 1024 * 1024) throw new Error('Unexpected QTS response');
            return text;
        } finally { clearTimeout(timer); }
    }
    async function identity(sid) {
        const xml = new DOMParser().parseFromString(await post('/cgi-bin/authLogin.cgi', { sid }), 'application/xml');
        if (xml.documentElement.nodeName !== 'QDocRoot' || xml.querySelector('parsererror')) {
            throw new Error('Unexpected QTS response');
        }
        const passed = xml.querySelector('authPassed')?.textContent.trim();
        if (passed !== '0' && passed !== '1') throw new Error('Unexpected QTS response');
        return { valid: passed === '1', username: xml.querySelector('username')?.textContent || '' };
    }
    function clearBrowserCredentials() {
        // Match native os.logout(): remove qtoken and NAS_SID; clear this
        // browsing context's QTS session storage. Also remove the saved account.
        // Other desktop preferences and trusted-device/vtoken data are retained.
        for (const key of ['qtoken', 'qtoken_account', 'NAS_SID']) localStorage.removeItem(key);
        sessionStorage.clear();
        const names = ['NAS_SID', 'NAS_USER', 'home', 'qtoken', 'qtoken_account',
            'remeber', 'nas_1_a', 'nas_1_u', 'QSYNC_SID', 'QMS_SSID', 'QMS_SID'];
        const domains = [''];
        let host = location.hostname;
        if (!/^[\d.]+$/.test(host) && !host.includes(':')) {
            while (host.includes('.')) {
                domains.push(host);
                host = host.slice(host.indexOf('.') + 1);
            }
        }
        for (const name of names) for (const domain of domains) {
            for (const path of ['/', '/cgi-bin', '/cgi-bin/', '/cgi-bin/login.html']) {
                document.cookie = name + '=; Max-Age=0; Path=' + path +
                    (domain ? '; Domain=' + domain : '') + '; SameSite=Lax' +
                    (location.protocol === 'https:' ? '; Secure' : '');
            }
        }
        return !localStorage.getItem('qtoken') && !localStorage.getItem('NAS_SID') && sessionStorage.length === 0;
    }
    async function performLogout() {
        if (location.origin !== QTS_ORIGIN) {
            return { ok: false, error: 'wrong_origin', expectedOrigin: QTS_ORIGIN };
        }
        const result = {
            ok: false, logoutRequestAccepted: false, rememberedLoginDeletionRequested: false,
            sessionRevoked: null, browserCredentialsCleared: false
        };
        let sid, qtoken, username, clientId;
        try {
            sid = localStorage.getItem('NAS_SID') || cookie('NAS_SID');
            qtoken = localStorage.getItem('qtoken') || cookie('qtoken');
            username = cookie('NAS_USER') || accountFromTokenLabel(localStorage.getItem('qtoken_account') || cookie('qtoken_account'));
            // Prefer the canonical account returned by the live NAS session.
            if (sid) {
                try {
                    const current = await identity(sid);
                    if (current.valid && current.username) username = current.username;
                } catch (_) { /* Still attempt native logout using the stored account. */ }
            }
            if (username) clientId = localStorage.getItem(username + (location.protocol === 'https:' ? 'SecureClientId' : 'ClientId'));
            const params = { logout: '1', del_client: '1' };
            if (username) params.user = username;
            if (clientId) params.client_id = clientId;
            if (qtoken) params.qtoken = qtoken;
            try {
                // Native os.logout() sends these same remembered-client parameters.
                // QTS getCgiUrl() puts SID in the query; other parameters are POSTed.
                const endpoint = '/cgi-bin/authLogout.cgi' + (sid ? '?sid=' + encodeURIComponent(sid) : '');
                await post(endpoint, params);
                result.logoutRequestAccepted = true;
                result.rememberedLoginDeletionRequested = Boolean(username && (clientId || qtoken));
            } catch (_) { result.error = 'logout_request_failed'; }
        } catch (_) { result.error = 'storage_unavailable'; }
        // Native logout clears browser credentials even when its Ajax call fails.
        try { result.browserCredentialsCleared = clearBrowserCredentials(); }
        catch (_) { result.error = 'browser_cleanup_failed'; }
        if (sid) {
            try { result.sessionRevoked = !(await identity(sid)).valid; }
            catch (_) { result.error = result.error || 'revocation_unverified'; }
        }
        // HTTP 200 alone does not establish that the old NAS session ended.
        result.ok = result.logoutRequestAccepted && result.browserCredentialsCleared &&
            (sid ? result.sessionRevoked === true : true) &&
            (!qtoken || result.rememberedLoginDeletionRequested);
        if (!result.ok && !result.error) result.error = 'logout_unverified';
        return result;
    }
    function logout() {
        if (!running) running = performLogout().finally(() => { running = undefined; });
        return running;
    }
    window.QTSLogoutHelper = Object.freeze({ version: 1, logout });
    // Future iframe clients: exact origin + parent window + correlation ID.
    // Never expose SID, qtoken, client ID, or username to the requesting app.
    window.addEventListener('message', async event => {
        const request = event.data;
        if (window.parent === window || event.source !== window.parent ||
            !ALLOWED_APP_ORIGINS.includes(event.origin) || !request ||
            request.type !== 'qts.logout' || typeof request.id !== 'string' ||
            !/^[A-Za-z0-9_-]{16,128}$/.test(request.id)) return;
        const result = await logout();
        event.source.postMessage({ type: 'qts.logout.result', id: request.id, ...result }, event.origin);
    });
})();
