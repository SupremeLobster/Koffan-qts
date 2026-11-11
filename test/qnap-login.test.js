const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../static/qnap-login.js'), 'utf8');

function browser({ qts = 'https://nas.example', app = 'https://nas.example:8443', next = '/lists/42', replies = [] } = {}) {
    const status = {};
    const frame = { addEventListener: (event, fn) => { handlers['frame:' + event] = fn; } };
    const help = { hidden: true };
    const timers = new Map();
    const handlers = {};
    const navigations = [];
    const requests = [];
    let now = 0;
    let timerID = 0;
    const document = {
        body: { dataset: { qtsLogin: qts + '/cgi-bin/login.html', next } },
        hidden: false,
        getElementById: id => id === 'status' ? status : id === 'login-help' ? help : frame,
        addEventListener: (event, fn) => { handlers[event] = fn; }
    };
    const origin = new URL(app);
    const window = {
        qnapTranslate: key => require('../i18n/en.json').qts[key],
        location: {
            origin: origin.origin, hostname: origin.hostname, protocol: origin.protocol,
            replace: target => navigations.push(target)
        },
        addEventListener: (event, fn) => { handlers[event] = fn; }
    };
    vm.runInNewContext(source, {
        URL, AbortController, document, window,
        Date: { now: () => now },
        setTimeout: (fn, delay) => { timers.set(++timerID, { fn, delay }); return timerID; },
        clearTimeout: id => timers.delete(id),
        fetch: async (url, options) => {
            requests.push({ url, options });
            const reply = replies.shift() || { status: 401 };
            if (reply instanceof Error) throw reply;
            if (typeof reply === 'function') return reply();
            return { status: reply.status, json: async () => ({ authenticated: reply.authenticated }) };
        }
    });
    return {
        status, frame, help, handlers, navigations, requests, timers,
        advance: delta => { now += delta; },
        runPoll: async () => {
            const entry = [...timers].find(([, timer]) => timer.delay === 3000);
            assert.ok(entry, 'next session check is scheduled');
            timers.delete(entry[0]);
            await entry[1].fn();
        }
    };
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('valid QTS session returns to the original Koffan page', async () => {
    const b = browser({ replies: [{ status: 200, authenticated: true }] });
    await settle();
    assert.equal(b.frame.src, 'https://nas.example/cgi-bin/login.html');
    assert.deepEqual(b.navigations, ['https://nas.example:8443/lists/42']);
    assert.equal(b.requests[0].url, '/auth/qts/status');
    assert.equal(b.requests[0].options.credentials, 'same-origin');
    assert.equal(b.requests[0].options.cache, 'no-store');
    assert.equal(b.timers.size, 0);
});

test('waits for QTS login, then automatically opens Koffan', async () => {
    const b = browser({ replies: [{ status: 401 }, { status: 200, authenticated: true }] });
    await settle();
    assert.equal(b.navigations.length, 0);
    await b.runPoll();
    assert.equal(b.navigations.length, 1);
    assert.equal(b.timers.size, 0);
});

test('returning from QTS in another tab checks immediately', async () => {
    const b = browser({ replies: [{ status: 401 }, { status: 200, authenticated: true }] });
    await settle();
    await b.handlers.focus();
    assert.equal(b.navigations.length, 1);
    assert.equal(b.timers.size, 0);
});

test('denied accounts stop polling', async () => {
    const b = browser({ replies: [{ status: 403 }] });
    await settle();
    assert.match(b.status.textContent, /not allowed/);
    assert.equal(b.navigations.length, 0);
    assert.equal(b.timers.size, 0);
});

test('NAS outages never count as successful authentication', async () => {
    const b = browser({ replies: [{ status: 503 }, new Error('offline'), { status: 200, authenticated: false }, { status: 200, authenticated: true }] });
    await settle();
    for (let i = 0; i < 2; i++) {
        assert.equal(b.navigations.length, 0);
        await b.runPoll();
    }
    assert.equal(b.navigations.length, 0);
    await b.runPoll();
    assert.equal(b.navigations.length, 1);
});

test('different hostnames, protocols, and external return URLs fail before loading QTS', () => {
    for (const options of [
        { app: 'https://other.example:8443' },
        { app: 'http://nas.example:3000' },
        { next: '//evil.example/' }
    ]) {
        const b = browser(options);
        assert.equal(b.frame.hidden, true);
        assert.equal(b.frame.src, undefined);
        assert.equal(b.requests.length, 0);
    }
});

test('focus changes cannot overlap an in-flight probe', async () => {
    let finish;
    const b = browser({ replies: [() => new Promise(resolve => { finish = resolve; })] });
    await b.handlers.focus();
    await b.handlers.visibilitychange();
    assert.equal(b.requests.length, 1);
    finish({ status: 401 });
    await settle();
    assert.equal([...b.timers.values()].filter(t => t.delay === 3000).length, 1);
});

test('polling ends after fifteen minutes or page navigation', async () => {
    const b = browser();
    await settle();
    b.advance(15 * 60 * 1000);
    await b.runPoll();
    assert.match(b.status.textContent, /timed out/);
    assert.equal(b.requests.length, 1);
    assert.equal(b.timers.size, 0);
    const other = browser();
    await settle();
    other.handlers.pagehide();
    assert.equal(other.timers.size, 0);
    await other.handlers.focus();
    assert.equal(other.requests.length, 1);
});


test('normal login keeps help hidden and loads the frame without a banner', async () => {
    const b = browser();
    await settle();
    assert.equal(b.help.hidden, true);
    b.handlers['frame:load']();
    assert.equal([...b.timers.values()].some(t => t.delay === 25000), false);
    assert.equal(b.help.hidden, true);
});

test('failed or stalled frame reveals fallback help', async () => {
    const b = browser();
    await settle();
    b.handlers['frame:error']();
    assert.equal(b.help.hidden, false);
    assert.match(b.status.textContent, /could not be loaded/);
    const stalled = browser();
    await settle();
    [...stalled.timers.values()].find(t => t.delay === 25000).fn();
    assert.equal(stalled.help.hidden, false);
    assert.match(stalled.status.textContent, /too long/);
});

test('recovery hides transient session errors without hiding a frame problem', async () => {
    const b = browser({ replies: [{ status: 503 }, { status: 401 }, { status: 401 }] });
    await settle();
    assert.equal(b.help.hidden, false);
    await b.runPoll();
    assert.equal(b.help.hidden, true);
    b.handlers['frame:error']();
    await b.runPoll();
    assert.equal(b.help.hidden, false);
    b.handlers['frame:load']();
    assert.equal(b.help.hidden, true);
});
