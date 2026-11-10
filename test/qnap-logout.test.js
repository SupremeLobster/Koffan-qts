const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../static/qnap-logout.js'), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

function browser({ disabled = false, blocked = false, verification = true, expired = false } = {}) {
    const removed = [], databases = [], deleted = [], navigations = [], requests = [], messages = [];
    const handlers = {}, frameHandlers = {}, timers = new Map();
    const token = '1'.repeat(64);
    let timerId = 0;
    const problem = { hidden: true }, status = {};
    const frame = {
        contentWindow: { postMessage: (data, origin) => messages.push({ data, origin }) },
        addEventListener: (event, callback) => { frameHandlers[event] = callback; },
        removeEventListener: event => { delete frameHandlers[event]; }
    };
    const fail = () => { throw new Error('storage disabled'); };
    const caches = {
        keys: disabled ? fail : async () => ['koffan-old-static', 'koffan-dynamic', 'another-app'],
        delete: async key => { deleted.push(key); }
    };
    const completion = vm.runInNewContext(source, {
        document: {
            body: { dataset: { logoutToken: token, helperUrl: 'https://nas.example:9443/qts-logout-helper.html', expired: String(expired) } },
            getElementById: id => id === 'qts-logout-helper' ? frame : id === 'logout-status' ? status : problem
        },
        localStorage: { removeItem: disabled ? fail : key => removed.push(key) },
        indexedDB: { deleteDatabase: disabled ? fail : name => {
            databases.push(name);
            const request = {};
            setImmediate(() => blocked ? request.onblocked() : request.onsuccess());
            return request;
        } }, caches, URL, AbortController,
        setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; },
        clearTimeout: id => timers.delete(id),
        fetch: async (url, options) => {
            requests.push({ url, options });
            return { ok: verification, json: async () => ({ logged_out: verification }) };
        },
        window: {
            caches, location: { replace: target => navigations.push(target) },
            addEventListener: (event, callback) => { handlers[event] = callback; },
            removeEventListener: event => { delete handlers[event]; }
        }
    });
    function reply(overrides = {}) {
        handlers.message?.({
            origin: 'https://nas.example:9443', source: frame.contentWindow,
            data: { type: 'qts.logout.result', id: token, ok: true, browserCredentialsCleared: true, logoutRequestAccepted: true },
            ...overrides
        });
    }
    return { completion, frame, frameHandlers, handlers, problem, status, timers, token,
        removed, databases, deleted, navigations, requests, messages, reply };
}

test('logout waits for the matching helper reply and server verification before navigation', async () => {
    const b = browser();
    await settle();
    assert.equal(b.frame.src, 'https://nas.example:9443/qts-logout-helper.html');
    assert.equal(b.problem.hidden, true);
    assert.deepEqual(b.requests, []);
    assert.deepEqual(b.navigations, []);
    b.frameHandlers.load();
    assert.equal(b.messages[0].origin, 'https://nas.example:9443');
    assert.equal(b.messages[0].data.type, 'qts.logout');
    assert.equal(b.messages[0].data.id, b.token);
    b.reply();
    await b.completion;
    assert.equal(b.requests[0].url, '/auth/qts/logout/complete');
    assert.equal(b.requests[0].options.headers['X-QTS-Logout-Token'], b.token);
    assert.equal(b.requests[0].options.method, 'POST');
    assert.deepEqual(b.navigations, ['/']);
    assert.deepEqual(b.removed, ['koffan-owner']);
    assert.deepEqual(b.databases, ['koffan-offline']);
    assert.deepEqual(b.deleted.sort(), ['koffan-dynamic', 'koffan-old-static']);
});

test('foreign windows, origins, IDs and message types cannot complete logout', async () => {
    const b = browser();
    b.reply({ origin: 'https://evil.example' });
    b.reply({ source: {} });
    b.reply({ data: { type: 'qts.logout.result', id: 'wrong', ok: true } });
    b.reply({ data: { type: 'other', id: b.token, ok: true } });
    await settle();
    assert.deepEqual(b.requests, []);
    assert.deepEqual(b.navigations, []);
    assert.equal(b.problem.hidden, true);
    b.reply();
    await b.completion;
    assert.deepEqual(b.navigations, ['/']);
});

test('helper failures and timeout show retry without reopening login', async () => {
    for (const mode of ['failed', 'timeout', 'load']) {
        const b = browser();
        if (mode === 'failed') b.reply({ data: { type: 'qts.logout.result', id: b.token, ok: false } });
        if (mode === 'timeout') [...b.timers.values()].find(timer => timer.delay === 35000).fn();
        if (mode === 'load') b.frameHandlers.error();
        await b.completion;
        assert.equal(b.problem.hidden, false);
        assert.match(b.status.textContent, /could not be confirmed/);
        assert.deepEqual(b.navigations, []);
        assert.deepEqual(b.requests, []);
    }
});

test('failed server verification cannot redirect to login', async () => {
    const b = browser({ verification: false });
    b.reply();
    await b.completion;
    assert.equal(b.problem.hidden, false);
    assert.deepEqual(b.navigations, []);
});

test('disabled or blocked offline storage does not prevent verified logout', async () => {
    for (const options of [{ disabled: true }, { blocked: true }]) {
        const b = browser(options);
        b.reply();
        await b.completion;
        assert.deepEqual(b.navigations, ['/']);
    }
});

test('expired server state stays on a retry screen', async () => {
    const b = browser({ expired: true });
    await b.completion;
    assert.equal(b.problem.hidden, false);
    assert.match(b.status.textContent, /expired/);
    assert.deepEqual(b.requests, []);
    assert.equal(b.frame.src, undefined);
});
