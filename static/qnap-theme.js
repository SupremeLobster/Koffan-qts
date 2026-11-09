// Match Koffan's saved theme before the login/logout page is painted.
(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    function applyTheme() {
        let stored;
        try { stored = localStorage.getItem('theme'); } catch (_) {}
        const dark = stored === 'dark' || (stored !== 'light' && media.matches);
        document.documentElement.classList.toggle('dark', dark);
        document.documentElement.classList.toggle('light', !dark);
    }
    applyTheme();
    window.addEventListener('storage', event => {
        if (event.key === 'theme' || event.key === null) applyTheme();
    });
    media.addEventListener('change', applyTheme);
})();
