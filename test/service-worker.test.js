const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadWorker(fetchImpl = async () => new Response('fresh'), options = {}) {
    const listeners = {};
    const entries = new Map();
    const key = request => typeof request === 'string' ? request : request.url;
    const cache = {
        async match(request) { return entries.get(key(request))?.clone(); },
        async addAll() {},
        async put(request, response) {
            if (options.quotaError) throw new Error('Quota exceeded');
            if (options.cachePut) await options.cachePut;
            entries.set(key(request), response);
        }
    };
    const context = vm.createContext({
        self: { location: { origin: 'http://localhost:3000' }, skipWaiting: async () => {}, addEventListener(name, fn) { listeners[name] = fn; } },
        caches: {
            open: async () => cache,
            keys: async () => ['koffan-old-dynamic'],
            delete: async () => { if (options.cacheDelete) await options.cacheDelete; entries.clear(); }
        },
        fetch: fetchImpl, URL, Response, AbortController, console,
        setTimeout: options.setTimeout || setTimeout,
        clearTimeout: options.clearTimeout || clearTimeout
    });
    vm.runInContext(fs.readFileSync(require.resolve('../static/sw.js'), 'utf8'), context);
    const background = [];
    function dispatch(path, mode = 'cors') {
        let response;
        const request = { url: new URL(path, 'http://localhost:3000').href, method: 'GET', mode, headers: new Headers({ accept: 'text/html' }) };
        listeners.fetch({ request, respondWith(value) { response = value; }, waitUntil(promise) { background.push(promise); } });
        return response;
    }
    return { listeners, dispatch, entries, settled: () => Promise.all(background) };
}

for (const path of ['/api/data', '/api/item/1/version', '/sections/1/items', '/stats', '/lists/1']) {
    test(`${path} background refresh cannot receive a stale successful fallback`, () => {
        const { dispatch } = loadWorker();
        assert.equal(dispatch(path), undefined, 'API and HTML fragments must use the actual network result');
    });
}

test('cross-origin requests are not intercepted', () => {
    assert.equal(loadWorker().dispatch('https://example.com/static/app.js'), undefined);
});

test('authentication documents and session probes never use the offline cache', () => {
    for (const path of ['/login', '/login?next=%2Flists%2F42', '/auth/qts/status', '/pwa-diagnostics']) {
        assert.equal(loadWorker().dispatch(path, 'navigate'), undefined);
    }
});

test('unmarked no-store documents are not saved for offline navigation', async () => {
    const { dispatch, entries, settled } = loadWorker(async () =>
        new Response('private shopping list', { headers: { 'Cache-Control': 'private, no-store' } }));
    assert.equal(await (await dispatch('/lists/1', 'navigate')).text(), 'private shopping list');
    await settled();
    assert.equal(entries.size, 0);
});

test('offline navigation returns the exact saved list', async () => {
    const { dispatch, entries } = loadWorker(async () => { throw new TypeError('Offline'); });
    entries.set('http://localhost:3000/lists/1', new Response('saved list 1'));
    entries.set('/', new Response('home'));
    assert.equal(await (await dispatch('/lists/1', 'navigate')).text(), 'saved list 1');
    const uncached = await dispatch('/lists/2', 'navigate');
    assert.equal(uncached.status, 503);
    assert.match(await uncached.text(), /This list is not saved offline/);
});

test('an uncached list uses the generic shopping shell while preserving the requested URL', async () => {
    const { dispatch, entries } = loadWorker(async () => { throw new TypeError('Offline'); });
    const shell = '<main data-list-id="0">Generic local shopping shell</main>';
    entries.set('/offline/list', new Response(shell));
    entries.set('/', new Response('Home overview'));
    entries.set('http://localhost:3000/lists/1', new Response('A different saved list'));
    for (const path of ['/lists/7', '/offline/list?list_id=-9']) {
        const response = await dispatch(path, 'navigate');
        assert.equal(response.status, 200);
        assert.equal(response.redirected, false, 'the browser keeps the requested list URL for the UI model');
        assert.equal(response.headers.get('Location'), null);
        assert.equal(await response.text(), shell);
    }
    assert.equal(await (await dispatch('/lists/1', 'navigate')).text(), 'A different saved list', 'an exact cached document still takes precedence');
});

test('unreachable mobile connection times out and loads saved navigation', async () => {
    let timeout;
    let delay;
    let cleared = false;
    const { dispatch, entries } = loadWorker((_request, { signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('Aborted')));
    }), {
        setTimeout(fn, ms) { timeout = fn; delay = ms; return 7; },
        clearTimeout(id) { assert.equal(id, 7); cleared = true; }
    });
    entries.set('http://localhost:3000/lists/1', new Response('saved list'));
    const result = dispatch('/lists/1', 'navigate');
    assert.equal(delay, 5000);
    timeout();
    assert.equal(await (await result).text(), 'saved list');
    assert.equal(cleared, true);
});

test('storage quota failure does not replace a successful server document', async () => {
    const { dispatch } = loadWorker(async () => new Response('fresh list'), { quotaError: true });
    assert.equal(await (await dispatch('/lists/1', 'navigate')).text(), 'fresh list');
});

test('a fresh document is returned before its offline copy is written', async () => {
    let finishWrite;
    const cachePut = new Promise(resolve => { finishWrite = resolve; });
    const { dispatch, entries, settled } = loadWorker(async () => new Response('fresh list'), { cachePut });
    assert.equal(await (await dispatch('/lists/1', 'navigate')).text(), 'fresh list');
    assert.equal(entries.has('http://localhost:3000/lists/1'), false, 'the page does not wait for Cache Storage');
    finishWrite();
    await settled();
    assert.equal(await entries.get('http://localhost:3000/lists/1').text(), 'fresh list');
});

test('login redirect cannot overwrite the saved list document', async () => {
    const redirect = new Response('login');
    Object.defineProperty(redirect, 'redirected', { value: true });
    const { dispatch, entries } = loadWorker(async () => redirect);
    entries.set('http://localhost:3000/lists/1', new Response('saved list'));
    assert.equal(await (await dispatch('/lists/1', 'navigate')).text(), 'login');
    assert.equal(await entries.get('http://localhost:3000/lists/1').text(), 'saved list');
});

test('navigation timeout remains active when headers arrive but the document body stalls', { timeout: 1000 }, async () => {
    let timeout;
    let cleared = false;
    const { dispatch, entries } = loadWorker(async (_request, { signal }) => {
        const body = new ReadableStream({
            start(controller) {
                controller.enqueue(new TextEncoder().encode('<html>partial document'));
                signal.addEventListener('abort', () => controller.error(new Error('Body aborted')));
            }
        });
        return new Response(body, { headers: { 'Content-Type': 'text/html' } });
    }, {
        setTimeout(fn) { timeout = fn; return 7; },
        clearTimeout(id) { assert.equal(id, 7); cleared = true; }
    });
    entries.set('http://localhost:3000/lists/1', new Response('complete saved list'));
    const result = dispatch('/lists/1', 'navigate');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(cleared, false, 'receiving only headers must not disable the navigation deadline');
    timeout();
    assert.equal(await (await result).text(), 'complete saved list');
    assert.equal(cleared, true);
    assert.equal(await entries.get('http://localhost:3000/lists/1').text(), 'complete saved list', 'partial document must not poison the offline cache');
});


test('explicit offline shopping opt-in saves private no-store documents', async () => {
    let online = true;
    const worker = loadWorker(async () => {
        if (!online) throw new TypeError('offline');
        return new Response('QTS shopping shell', { headers: { 'Cache-Control': 'private, no-store', 'X-Koffan-Offline': 'shopping-v1' } });
    });
    await worker.dispatch('/lists/1', 'navigate');
    await worker.settled();
    online = false;
    const saved = await worker.dispatch('/lists/1', 'navigate');
    assert.equal(await saved.text(), 'QTS shopping shell');
    assert.match(saved.headers.get('Cache-Control'), /no-store/);
});

test('installation precaches QTS shopping shells using the same opt-in', async () => {
    const worker = loadWorker(async () => new Response('QTS shopping shell', { headers: { 'Cache-Control': 'private, no-store', 'X-Koffan-Offline': 'shopping-v1' } }));
    let done;
    worker.listeners.install({ waitUntil: promise => { done = promise; } });
    await done;
    assert.equal(await worker.entries.get('/').text(), 'QTS shopping shell');
    assert.equal(await worker.entries.get('/offline/list').text(), 'QTS shopping shell');
});

test('temporary NAS errors preserve offline shopping without replacing the saved copy', async () => {
    const worker = loadWorker(async () => new Response('QTS unavailable', { status: 503 }));
    worker.entries.set('http://localhost:3000/lists/1', new Response('saved list'));
    assert.equal(await (await worker.dispatch('/lists/1','navigate')).text(), 'saved list');
    assert.equal(await worker.entries.get('http://localhost:3000/lists/1').text(), 'saved list');
    const uncached = await worker.dispatch('/lists/2','navigate');
    assert.equal(uncached.status, 503);
});

for (const status of [401,403]) test(`known authorization failure ${status} never falls back to private offline data`, async () => {
    const worker = loadWorker(async () => new Response('sign in required', { status }));
    worker.entries.set('http://localhost:3000/lists/1', new Response('saved list'));
    assert.equal((await worker.dispatch('/lists/1','navigate')).status, status);
});


test('account cleanup finishes before refilling the new offline shell', async () => {
    let finishDelete;
    const cacheDelete = new Promise(resolve => { finishDelete = resolve; });
    let fetches = 0;
    const worker = loadWorker(async () => {
        fetches++;
        return new Response('new account shopping shell', { headers: { 'Cache-Control': 'private, no-store', 'X-Koffan-Offline': 'shopping-v1' } });
    }, { cacheDelete });
    worker.entries.set('/offline/list', new Response('previous account shell'));
    const jobs = [];
    for (const type of ['CLEAR_CACHE','CACHE_OFFLINE_SHELL']) worker.listeners.message({ data: { type }, waitUntil: promise => jobs.push(promise) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(fetches, 0, 'new shell must not be written into a cache being deleted');
    finishDelete();
    await Promise.all(jobs);
    assert.equal(await worker.entries.get('/offline/list').text(), 'new account shopping shell');
    assert.equal(await worker.entries.get('/').text(), 'new account shopping shell');
});

test('manifest revalidates its stable URL instead of returning stale static metadata', async () => {
    const worker=loadWorker(async (request,options)=>{
        assert.equal(options.cache,'no-cache');
        return new Response('{"name":"Koffan Shopping List"}',{headers:{'Content-Type':'application/manifest+json'}});
    });
    worker.entries.set('http://localhost:3000/static/manifest.json',new Response('{"short_name":"Koffan"}'));
    const response=await worker.dispatch('/static/manifest.json');
    assert.equal((await response.json()).name,'Koffan Shopping List');
    assert.equal((await worker.entries.get('http://localhost:3000/static/manifest.json').json()).name,'Koffan Shopping List');
});

test('offline manifest requests retain the last saved installation metadata', async () => {
    const worker=loadWorker(async()=>{throw new Error('offline')});
    worker.entries.set('http://localhost:3000/static/manifest.json',new Response('{"name":"Koffan Shopping List"}'));
    assert.equal((await(await worker.dispatch('/static/manifest.json')).json()).name,'Koffan Shopping List');
});
