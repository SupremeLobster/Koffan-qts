const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../static/qnap-logout.js'), 'utf8');

function browser({ disabled = false, blocked = false } = {}) {
    const removed = [], databases = [], deleted = [], navigations = [];
    let request;
    const fail = () => { throw new Error('storage disabled'); };
    const caches = {
        keys: disabled ? fail : async () => ['koffan-old-static', 'koffan-dynamic', 'another-app'],
        delete: async key => { deleted.push(key); }
    };
    const completion = vm.runInNewContext(source, {
        localStorage: { removeItem: disabled ? fail : key => removed.push(key) },
        indexedDB: { deleteDatabase: disabled ? fail : name => {
            databases.push(name);
            request = {};
            if (blocked) setImmediate(() => request.onblocked());
            return request;
        } },
        caches, setTimeout, clearTimeout,
        window: { caches, location: { replace: target => navigations.push(target) } }
    });
    return { removed, databases, deleted, navigations, completion, get request() { return request; } };
}

test('logout waits for browser cleanup then returns to the app root', async () => {
    const b = browser();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(b.navigations, []);
    b.request.onsuccess();
    await b.completion;
    assert.deepEqual(b.removed, ['koffan-owner']);
    assert.deepEqual(b.databases, ['koffan-offline']);
    assert.deepEqual(b.deleted.sort(), ['koffan-dynamic', 'koffan-old-static']);
    assert.deepEqual(b.navigations, ['/']);
});

test('disabled or blocked browser storage still returns to login', async () => {
    for (const options of [{ disabled: true }, { blocked: true }]) {
        const b = browser(options);
        await b.completion;
        assert.deepEqual(b.navigations, ['/']);
    }
});
