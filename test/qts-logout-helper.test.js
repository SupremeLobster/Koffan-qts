const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../tools/qts-logout-helper/qts-logout-helper.js'), 'utf8');

function environment({ failure = false, revoke = true, origin = 'https://shopping.mafucat.com:9443' } = {}) {
    const stored = new Map([
        ['NAS_SID', 'old-sid'], ['qtoken', 'remember-token'], ['qtoken_account', btoa('admin')],
        ['adminSecureClientId', 'client-id'], ['desktop_preference', 'keep']
    ]);
    const calls = [], messages = [], handlers = {};
    const parent = {};
    let valid = true, sessionLength = 2;
    const storage = {
        getItem: key => stored.get(key) || null, removeItem: key => stored.delete(key)
    };
    const document = { cookie: 'NAS_USER=forged-name; NAS_SID=old-sid' };
    const window = {
        parent, addEventListener: (event, callback) => { handlers[event] = callback; }
    };
    class DOMParser {
        parseFromString(text) {
            return {
                documentElement: { nodeName: text.startsWith('<QDocRoot>') ? 'QDocRoot' : 'html' },
                querySelector: name => {
                    const match = text.match(new RegExp('<' + name + '>([^<]*)</' + name + '>'));
                    return match ? { textContent: match[1] } : null;
                }
            };
        }
    }
    vm.runInNewContext(source, {
        window, document, location: new URL(origin), localStorage: storage,
        sessionStorage: { clear: () => { sessionLength = 0; }, get length() { return sessionLength; } },
        DOMParser, AbortController, URLSearchParams, setTimeout, clearTimeout, atob,
        fetch: async (url, options) => {
            calls.push({ url, options, params: new URLSearchParams(options.body) });
            if (url.startsWith('/cgi-bin/authLogout.cgi')) {
                if (failure) return { ok: false };
                if (revoke) valid = false;
                return { ok: true, text: async () => '<QDocRoot><authPassed>0</authPassed></QDocRoot>' };
            }
            return { ok: true, text: async () => valid
                ? '<QDocRoot><authPassed>1</authPassed><username>admin</username></QDocRoot>'
                : '<QDocRoot><authPassed>0</authPassed></QDocRoot>' };
        }
    });
    parent.postMessage = (message, target) => { messages.push({ message, target }); };
    return { helper: window.QTSLogoutHelper, stored, calls, messages, handlers, parent, get sessionLength() { return sessionLength; } };
}

test('helper matches native remembered-client logout and verifies revocation', async () => {
    const e = environment();
    assert.equal(e.calls.length, 0, 'loading the helper must not log out');
    const result = await e.helper.logout();
    assert.equal(result.ok, true);
    assert.equal(result.sessionRevoked, true);
    assert.equal(result.rememberedLoginDeletionRequested, true);
    const call = e.calls.find(call => call.url.includes('authLogout.cgi'));
    assert.equal(call.url, '/cgi-bin/authLogout.cgi?sid=old-sid');
    assert.equal(call.options.method, 'POST');
    assert.equal(call.options.credentials, 'same-origin');
    assert.equal(call.options.redirect, 'error');
    assert.deepEqual(Object.fromEntries(call.params), {
        logout: '1', del_client: '1', user: 'admin', client_id: 'client-id', qtoken: 'remember-token'
    });
    assert.equal(e.stored.has('NAS_SID'), false);
    assert.equal(e.stored.has('qtoken'), false);
    assert.equal(e.stored.get('desktop_preference'), 'keep');
    assert.equal(e.sessionLength, 0);
    assert.equal(JSON.stringify(result).includes('remember-token'), false);
    assert.equal(JSON.stringify(result).includes('old-sid'), false);
});

test('HTTP success without revocation is not reported as logout success', async () => {
    const e = environment({ revoke: false });
    const result = await e.helper.logout();
    assert.equal(result.ok, false);
    assert.equal(result.sessionRevoked, false);
    assert.equal(result.browserCredentialsCleared, true);
});

test('NAS failure still clears browser credentials and reports failure', async () => {
    const e = environment({ failure: true });
    const result = await e.helper.logout();
    assert.equal(result.ok, false);
    assert.equal(result.logoutRequestAccepted, false);
    assert.equal(result.browserCredentialsCleared, true);
});

test('wrong origin cannot clear the wrong site', async () => {
    const e = environment({ origin: 'https://shopping.mafucat.com' });
    const result = await e.helper.logout();
    assert.equal(result.error, 'wrong_origin');
    assert.equal(e.calls.length, 0);
    assert.equal(e.stored.has('qtoken'), true);
});

test('iframe requests require the allowed parent and a correlation ID', async () => {
    const e = environment();
    const data = { type: 'qts.logout', id: 'valid_test_request_123' };
    for (const event of [
        { source: e.parent, origin: 'https://evil.example', data },
        { source: {}, origin: 'https://shopping.mafucat.com', data },
        { source: e.parent, origin: 'https://shopping.mafucat.com', data: { ...data, id: '*' } }
    ]) await e.handlers.message(event);
    assert.equal(e.calls.length, 0);
    await e.handlers.message({ source: e.parent, origin: 'https://shopping.mafucat.com', data });
    assert.equal(e.messages.length, 1);
    assert.equal(e.messages[0].target, 'https://shopping.mafucat.com');
    assert.equal(e.messages[0].message.id, data.id);
    assert.equal(e.messages[0].message.ok, true);
});
