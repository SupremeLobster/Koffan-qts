(() => {
    'use strict';
    const t = window.qnapTranslate;
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
        showProblem(t('host_mismatch'));
        frame.hidden = true;
        return;
    }
    if (qtsURL.protocol !== window.location.protocol) {
        showProblem(t('protocol_mismatch'));
        frame.hidden = true;
        return;
    }
    let frameTimer = setTimeout(() => {
        showFrameProblem(t('load_slow'));
    }, 25000);
    frame.addEventListener('load', () => {
        clearTimeout(frameTimer);
        showFrameProblem('');
    });
    frame.addEventListener('error', () => {
        clearTimeout(frameTimer);
        showFrameProblem(t('load_failed'));
    });
    document.addEventListener('securitypolicyviolation', event => {
        if (event.effectiveDirective === 'frame-src' && (event.blockedURI === qtsURL.origin || event.blockedURI === qtsURL.href)) {
            clearTimeout(frameTimer);
            showFrameProblem(t('frame_blocked'));
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
            showProblem(t('login_timeout'));
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
                showProblem(t('account_denied'));
                return;
            }
            showSessionProblem(response.status === 401 ? '' : t('auth_unavailable'));
        } catch {
            showSessionProblem(t('session_check_failed'));
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
