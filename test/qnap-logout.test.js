const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../static/qnap-logout.js'), 'utf8');

test('logout clears Koffan offline state without navigating back into login', async () => {
    const removed = [];
    const databases = [];
    const cachesDeleted = [];
    const cacheStorage = {
        keys: async () => ['koffan-old-static', 'koffan-dynamic', 'another-app'],
        delete: async key => { cachesDeleted.push(key); }
    };
    await vm.runInNewContext(source, {
        localStorage: { removeItem: key => removed.push(key) },
        indexedDB: { deleteDatabase: name => databases.push(name) },
        caches: cacheStorage,
        window: { caches: cacheStorage }
    });
    assert.deepEqual(removed, ['koffan-owner']);
    assert.deepEqual(databases, ['koffan-offline']);
    assert.deepEqual(cachesDeleted.sort(), ['koffan-dynamic', 'koffan-old-static']);
});

test('disabled browser storage does not prevent logout completion', async () => {
    const fail = () => { throw new Error('storage disabled'); };
    await vm.runInNewContext(source, {
        localStorage: { removeItem: fail }, indexedDB: { deleteDatabase: fail },
        caches: { keys: fail }, window: { caches: {} }
    });
});
