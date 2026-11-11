// Read-only on-device diagnostics, including old metadata held by older workers.
(() => {
    'use strict';
    const output = document.getElementById('report');
    const status = document.getElementById('status');
    const findings = document.getElementById('findings');
    function safeURL(value, base = location.origin) {
        try {
            const url = new URL(value, base);
            // Preserve only our public asset version. Never copy arbitrary URL parameters.
            const version = url.searchParams.get('v');
            return url.origin + url.pathname + (version && /^[a-f0-9]{8,64}$/.test(version) ? '?v=' + version : '');
        } catch (_) { return null; }
    }
    function manifestLink(html, base) {
        const document = new DOMParser().parseFromString(html, 'text/html');
        const href = document.querySelector('link[rel="manifest"]')?.getAttribute('href');
        return href ? safeURL(href, base) : null;
    }
    async function get(url, credentials = 'omit') {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 12000);
        try {
            const response = await fetch(url, { credentials, cache: 'no-store', signal: controller.signal });
            const bytes = await response.arrayBuffer();
            if (bytes.byteLength > 2 * 1024 * 1024) throw new Error('response_too_large');
            return { response, bytes };
        } finally { clearTimeout(timer); }
    }
    async function manifest(url) {
        try {
            const { response, bytes } = await get(url);
            const result = {
                url: safeURL(response.url), status: response.status, redirected: response.redirected,
                contentType: response.headers.get('Content-Type'), cacheControl: response.headers.get('Cache-Control'),
                assetVersion: response.headers.get('X-Koffan-Asset-Version'), bytes: bytes.byteLength
            };
            if (!response.ok) return result;
            const data = JSON.parse(new TextDecoder().decode(bytes));
            result.name = data.name;
            result.shortName = data.short_name;
            result.id = safeURL(data.id || data.start_url || '/', response.url);
            result.startURL = safeURL(data.start_url || '/', response.url);
            result.scope = data.scope ? safeURL(data.scope, response.url) : null;
            result.display = data.display;
            result.icons = (data.icons || []).map(icon => ({
                url: safeURL(icon.src, response.url), sizes: icon.sizes, type: icon.type, purpose: icon.purpose
            }));
            return result;
        } catch (error) { return { error: error.name }; }
    }
    async function checkIcon(icon, stamp) {
        if (!icon.url || new URL(icon.url).origin !== location.origin) return { ...icon, error: 'different_origin' };
        try {
            const url = new URL(icon.url);
            url.searchParams.set('pwa-check', stamp);
            const { response, bytes } = await get(url);
            const result = { ...icon, status: response.status, redirected: response.redirected,
                contentType: response.headers.get('Content-Type'), bytes: bytes.byteLength };
            if (response.ok) {
                const bitmap = await createImageBitmap(new Blob([bytes], { type: result.contentType }));
                result.width = bitmap.width; result.height = bitmap.height; bitmap.close();
            }
            return result;
        } catch (error) { return { ...icon, error: error.name }; }
    }
    function finding(text) {
        const item = document.createElement('li'); item.textContent = text; findings.append(item);
    }
    async function run() {
        document.getElementById('rerun').disabled = true;
        status.textContent = 'Checking…'; findings.replaceChildren(); output.value = '';
        const stamp = String(Date.now());
        const report = {
            diagnosticVersion: 1, origin: location.origin, secureContext: window.isSecureContext,
            browser: navigator.userAgent, online: navigator.onLine
        };
        try {
            if (navigator.userAgentData?.getHighEntropyValues) {
                try { report.platform = await navigator.userAgentData.getHighEntropyValues(['platformVersion', 'fullVersionList']); } catch (_) {}
            }
            const [stable, fresh] = await Promise.all([
                manifest('/static/manifest.json'), manifest('/static/manifest.json?pwa-check=' + stamp)
            ]);
            report.browserManifest = stable;
            report.freshServerManifest = fresh;
            report.icons = await Promise.all((fresh.icons || []).map(icon => checkIcon(icon, stamp)));
            try {
                const { response, bytes } = await get('/?pwa-check=' + stamp, 'same-origin');
                report.currentPage = { status: response.status, redirected: response.redirected,
                    manifestURL: manifestLink(new TextDecoder().decode(bytes), response.url) };
            } catch (error) { report.currentPage = { error: error.name }; }
            report.serviceWorker = { supported: 'serviceWorker' in navigator };
            if ('serviceWorker' in navigator) {
                report.serviceWorker.controller = navigator.serviceWorker.controller ? safeURL(navigator.serviceWorker.controller.scriptURL) : null;
                report.serviceWorker.registrations = (await navigator.serviceWorker.getRegistrations()).map(reg => ({
                    scope: safeURL(reg.scope), active: reg.active?.state || null,
                    waiting: reg.waiting?.state || null, installing: reg.installing?.state || null
                }));
            }
            report.cachedPages = [];
            if ('caches' in window) {
                report.appCaches = (await caches.keys()).filter(key => /^koffan-[a-f0-9_]+-(static|dynamic)$/.test(key));
                for (const name of report.appCaches.filter(key => key.endsWith('-dynamic'))) {
                    const saved = await (await caches.open(name)).match('/');
                    if (saved) report.cachedPages.push({ cache: name, manifestURL: manifestLink(await saved.text(), location.origin) });
                }
            }
            if (fresh.error || fresh.status !== 200 || fresh.redirected) finding('The server manifest could not be fetched publicly as a successful response.');
            else finding('The server manifest is accessible without a QTS cookie.');
            if (fresh.name !== stable.name || fresh.shortName !== stable.shortName || fresh.id !== stable.id || fresh.assetVersion !== stable.assetVersion) {
                finding('The browser and fresh server manifest differ: an old worker or cached response may be involved.');
            }
            if (report.currentPage?.manifestURL?.includes('?v=')) finding('The app page still links to a versioned manifest URL.');
            else if (report.currentPage?.manifestURL) finding('The app page links to an unversioned manifest URL.');
            else finding('The current page has no manifest link. Open Koffan, sign in if needed, then run this check again.');
            if (report.cachedPages.some(page => page.manifestURL?.includes('?v='))) finding('A saved app page still contains an older versioned manifest link.');
            if (report.icons.some(icon => icon.status !== 200 || icon.redirected || icon.error)) finding('At least one installation icon could not be fetched and decoded publicly.');
            else if (report.icons.length) finding('Installation icons are accessible and decode successfully.');
            finding('These page checks cannot read Chrome Beta’s Android package-install queue or Google’s WebAPK service result.');
        } catch (error) { report.error = error.name; }
        output.value = JSON.stringify(report, null, 2);
        status.textContent = 'Checks finished. Copy the report to share the results.';
        document.getElementById('rerun').disabled = false;
    }
    document.getElementById('rerun').addEventListener('click', run);
    document.getElementById('copy').addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(output.value); status.textContent = 'Report copied.'; }
        catch (_) { output.focus(); output.select(); status.textContent = 'Select and copy the report below.'; }
    });
    run();
})();
