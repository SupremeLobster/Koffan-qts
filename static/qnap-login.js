(() => {
    'use strict';
    const status = document.getElementById('status');
    const help = document.getElementById('login-help');
    const frame = document.getElementById('qts-login');
    const qtsURL = new URL(document.body.dataset.qtsLogin);
    const next = new URL(document.body.dataset.next, window.location.origin);
    let frameProblem = '', sessionProblem = '', terminalProblem = '';
    function renderProblem() {
        const message = terminalProblem || frameProblem || sessionProblem;
        status.textContent = message;
        help.hidden = !message;
    }
    function showProblem(message) { terminalProblem = message; renderProblem(); }
    function showFrameProblem(message) { frameProblem = message; renderProblem(); }
    function showSessionProblem(message) { sessionProblem = message; renderProblem(); }
    // Cookies are scoped to host and path, not port.
    if (qtsURL.hostname !== window.location.hostname || next.origin !== window.location.origin) {
        showProblem('Open Koffan and QTS using exactly the same NAS hostname or IP address. Different ports are supported.');
        frame.hidden = true;
        return;
    }
    if (qtsURL.protocol !== window.location.protocol) {
        showProblem('Open Koffan and QTS over the same protocol. Use HTTPS for both so the browser can send the secure QTS cookie.');
        frame.hidden = true;
        return;
    }
    let frameTimer = setTimeout(() => {
        showFrameProblem('The QTS sign-in screen is taking too long to load.');
    }, 25000);
    frame.addEventListener('load', () => {
        clearTimeout(frameTimer);
        showFrameProblem('');
    });
    frame.addEventListener('error', () => {
        clearTimeout(frameTimer);
        showFrameProblem('The QTS sign-in screen could not be loaded.');
    });
    document.addEventListener('securitypolicyviolation', event => {
        if (event.effectiveDirective === 'frame-src' && (event.blockedURI === qtsURL.origin || event.blockedURI === qtsURL.href)) {
            clearTimeout(frameTimer);
            showFrameProblem('The browser blocked the QTS sign-in screen.');
        }
    });
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
            clearTimeout(frameTimer);
            showProblem('Sign-in timed out. Reload this page to try again.');
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
                clearTimeout(frameTimer);
                window.location.replace(next.href);
                return;
            }
            if (response.status === 403) {
                stopped = true;
                clearTimeout(frameTimer);
                showProblem('This QTS account is not allowed to use Koffan.');
                return;
            }
            showSessionProblem(response.status === 401 ? '' : 'QTS authentication is unavailable. Retrying…');
        } catch {
            showSessionProblem('Cannot check your QTS session. Retrying…');
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
        clearTimeout(frameTimer);
    });
    checkSession();
})();
