(() => {
    'use strict';
    const status = document.getElementById('status');
    const form = document.getElementById('qts-login-form');
    const password = document.getElementById('qts-password');
    const code = document.getElementById('qts-code');
    const submit = document.getElementById('qts-submit');
    const next = new URL(document.body.dataset.next, window.location.origin);
    if (next.origin !== window.location.origin) {
        status.textContent = 'Invalid return address. Open Koffan again.';
        submit.disabled = true;
        return;
    }
    if (window.location.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(window.location.hostname)) {
        status.textContent = 'Open Koffan over HTTPS before signing in.';
        submit.disabled = true;
        return;
    }
    let timer;
    let checking = false;
    let submitting = false;
    let stopped = false;
    const deadline = Date.now() + 15 * 60 * 1000;
    form.addEventListener('input', event => {
        if (event.target.name === 'username') {
            code.required = false;
            code.value = '';
        }
    });
    function scheduleCheck() {
        clearTimeout(timer);
        if (!stopped) timer = setTimeout(checkSession, 3000);
    }
    async function checkSession() {
        if (checking || submitting || stopped) return;
        clearTimeout(timer);
        if (Date.now() >= deadline) { stopped = true; return; }
        checking = true;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        try {
            const response = await fetch('/auth/qts/status', {
                credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
                redirect: 'error', headers: { Accept: 'application/json' }
            });
            if (!submitting && response.status === 200) {
                const result = await response.json();
                if (!submitting && result.authenticated === true) {
                    stopped = true;
                    window.location.replace(next.href);
                }
            }
        } catch (_) {
            // A failed background check must not erase form errors or credentials.
        } finally {
            clearTimeout(timeout);
            checking = false;
            scheduleCheck();
        }
    }
    form.addEventListener('submit', async event => {
        event.preventDefault();
        if (submitting || !form.reportValidity()) return;
        submitting = true;
        clearTimeout(timer);
        submit.disabled = true;
        submit.textContent = 'Signing in…';
        form.setAttribute('aria-busy', 'true');
        status.textContent = 'Checking your QTS account…';
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 25000);
        try {
            const response = await fetch('/auth/qts/login', {
                method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
                signal: controller.signal,
                headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(new FormData(form))
            });
            const result = await response.json();
            if (response.ok && result.authenticated === true) {
                const destination = new URL(result.redirect || '/', window.location.origin);
                if (destination.origin !== window.location.origin) throw new Error('Invalid return address');
                password.value = '';
                code.value = '';
                stopped = true;
                window.location.replace(destination.href);
                return;
            }
            status.textContent = result.message || 'Sign-in failed. Try again.';
            if (result.error === 'security_code_required') {
                code.required = true;
                code.focus();
            } else if (result.error === 'invalid_credentials' || result.error === 'invalid_code') {
                code.value = '';
                if (code.required) code.focus();
            }
        } catch (_) {
            status.textContent = 'Could not complete sign-in. Check your connection and try again.';
        } finally {
            clearTimeout(timeout);
            submitting = false;
            submit.disabled = false;
            submit.textContent = 'Sign in';
            form.removeAttribute('aria-busy');
            scheduleCheck();
        }
    });
    window.addEventListener('focus', checkSession);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) checkSession(); });
    window.addEventListener('pagehide', () => { stopped = true; clearTimeout(timer); });
    checkSession();
})();
