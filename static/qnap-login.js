(() => {
    'use strict';
    const status = document.getElementById('status');
    const frame = document.getElementById('qts-login');
    const qtsURL = new URL(document.body.dataset.qtsLogin);
    const next = new URL(document.body.dataset.next, window.location.origin);
    // Cookies are scoped to host and path, not port.
    if (qtsURL.hostname !== window.location.hostname || next.origin !== window.location.origin) {
        status.textContent = 'Open Koffan and QTS using exactly the same NAS hostname or IP address. Different ports are supported.';
        frame.hidden = true;
        return;
    }
    if (qtsURL.protocol !== window.location.protocol) {
        status.textContent = 'Open Koffan and QTS over the same protocol. Use HTTPS for both so the browser can send the secure QTS cookie.';
        frame.hidden = true;
        return;
    }
    frame.src = qtsURL.href;
    let timer;
    let checking = false;
    let stopped = false;
    const deadline = Date.now() + 15 * 60 * 1000;
    async function checkSession() {
        if (checking || stopped) return;
        clearTimeout(timer);
        if (Date.now() >= deadline) {
            stopped = true;
            status.textContent = 'Sign-in timed out. Reload this page to try again.';
            return;
        }
        checking = true;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        try {
            const response = await fetch('/auth/qts/status', {
                credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
                redirect: 'error', headers: { Accept: 'application/json' }
            });
            if (response.status === 200 && (await response.json()).authenticated === true) {
                stopped = true;
                window.location.replace(next.href);
                return;
            }
            if (response.status === 403) {
                stopped = true;
                status.textContent = 'This QTS account is not allowed to use Koffan.';
                return;
            }
            status.textContent = response.status === 401
                ? 'Sign in to QTS. Koffan will open automatically when you are signed in.'
                : 'QTS authentication is unavailable. Retrying…';
        } catch {
            status.textContent = 'Cannot check your QTS session. Retrying…';
        } finally {
            clearTimeout(timeout);
            checking = false;
            if (!stopped) timer = setTimeout(checkSession, 3000);
        }
    }
    window.addEventListener('focus', checkSession);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) checkSession();
    });
    window.addEventListener('pagehide', () => {
        stopped = true;
        clearTimeout(timer);
    });
    checkSession();
})();
