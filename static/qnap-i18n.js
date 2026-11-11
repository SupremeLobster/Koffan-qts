// Standalone QTS pages use the same saved preference as the shopping UI.
(() => {
    'use strict';
    const config = JSON.parse(document.getElementById('qts-translations').textContent);
    let lang = config.lang;
    try {
        const stored = localStorage.getItem('language');
        if (stored && config.locales[stored]) lang = stored;
        // Logout clears cookies, but the user's explicit language choice remains.
        if (stored && config.locales[stored]) {
            document.cookie = 'lang=' + encodeURIComponent(lang) + '; Path=/; Max-Age=31536000; SameSite=Lax' +
                (location.protocol === 'https:' ? '; Secure' : '');
        }
    } catch (_) {}
    const selected = config.locales[lang] || config.locales.en || {};
    const english = config.locales.en || {};
    const t = key => selected[key] || english[key] || key;
    window.qnapTranslate = t;
    document.documentElement.lang = lang;
    for (const el of document.querySelectorAll('[data-qts-text]')) el.textContent = t(el.dataset.qtsText);
    for (const el of document.querySelectorAll('[data-qts-title]')) el.title = t(el.dataset.qtsTitle);
    document.title = t(document.body.dataset.qtsPageTitle) + ' · Koffan';
})();
