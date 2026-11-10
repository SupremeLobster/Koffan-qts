# Standalone QTS logout helper

This is independent of Koffan. It duplicates the authentication-relevant logout
steps found in the NAS-provided `qos-core-base.js`, `qos-core-login.js`, and
`qos-lib.js`; it does not load QTS's desktop framework. No logout happens merely
by downloading or loading the helper.

The defaults target:

- QTS origin: `https://shopping.mafucat.com:9443`
- Allowed application origin: `https://shopping.mafucat.com`

For another NAS/application, edit `QTS_ORIGIN` and `ALLOWED_APP_ORIGINS` at the top
of the JavaScript. Origins include protocol and port, with no trailing slash or
path. Multiple applications can be explicitly listed; do not use a wildcard.

## Install on the NAS

Over SSH as an administrator, download the JavaScript into QTS's administration
web root (not `/home/Qhttpd` and not the Web shared folder):

```sh
curl -fL 'https://raw.githubusercontent.com/SupremeLobster/Koffan-qts/qnap-qts-auth/tools/qts-logout-helper/qts-logout-helper.js' -o /home/httpd/qts-logout-helper.js
chmod 644 /home/httpd/qts-logout-helper.js
```

Run those commands as root, or prefix them with `sudo` if your account needs it.
Alternatively, copy the downloaded JavaScript file to that exact location.
This adds a file; it does not replace QTS's scripts or change QTS configuration.
Verify your firmware serves it at:

`https://shopping.mafucat.com:9443/qts-logout-helper.js`

If it returns 404, a login page, or a forbidden response, the QTS management
server is not serving that path; do not substitute a different origin/port.
The installation has not been verified on the actual NAS. Firmware updates or
reboots may remove files in the administration web root; retain a backup.

## Minimal console test

1. Sign in to QTS with **Keep me logged in** enabled. For this first test, close
   other QTS/Koffan tabs that could perform concurrent session checks.
2. On the actual QTS tab at `https://shopping.mafucat.com:9443`, open the browser
   developer console. Select the top-level QTS execution context.
3. Run:

```js
if (location.origin !== 'https://shopping.mafucat.com:9443') throw new Error('Run this in the QTS tab on port 9443');
const helperResponse = await fetch('/qts-logout-helper.js', { cache: 'no-store' });
if (!helperResponse.ok) throw new Error('Helper could not be loaded');
(0, eval)(await helperResponse.text());
await window.QTSLogoutHelper.logout();
```

This **does log out** the current QTS browser session and asks QTS to delete its
remembered client. It is not a dry run. It does not ask for a password, print
stored tokens, navigate away, or return credentials to an application.

If the browser's Content Security Policy rejects `eval`, use this instead:

```js
await import('/qts-logout-helper.js?test=' + Date.now());
await window.QTSLogoutHelper.logout();
```

For a successful test, the result should include:

```js
{
  ok: true,
  logoutRequestAccepted: true,
  rememberedLoginDeletionRequested: true,
  sessionRevoked: true,
  browserCredentialsCleared: true
}
```

`sessionRevoked` is `null` if there was no previous SID to verify. A remembered
client is requested for deletion only when its username and token/client ID are
available. `logoutRequestAccepted` means the endpoint returned HTTP success;
`sessionRevoked` separately checks the old SID using the authentication API.
The helper does **not** try the old remembered token again, because that could
create a fresh NAS session. Its server-side revocation must be confirmed by the
following real-NAS browser check.

After running the command, navigate to
`https://shopping.mafucat.com:9443/cgi-bin/login.html` and reload it. You should
remain on the login screen rather than automatically returning to the desktop.
Check that local storage no longer contains `qtoken` or `NAS_SID`.
Other desktop preference entries can remain; clearing all local storage is not
required for logout. If `ok` is false or auto-login persists, report the result
object and whether those two keys remain; do not share token/cookie values.

## What the helper does

- Reads the current SID, stored username, remembered token, and per-user client
  ID from **the QTS origin**. It prefers the account verified by the live SID.
- Sends `logout=1`, `del_client=1`, `user`, and any available `client_id`/`qtoken`
  to `/cgi-bin/authLogout.cgi`. Like native `getCgiUrl()`, it places SID in the
  query; the other fields use a POST body. Credentials stay at the QTS origin.
- Removes `qtoken` and `NAS_SID` from local storage and clears session storage
  for this browsing context, matching native `os.logout()`. It additionally
  removes the saved `qtoken_account` label and legacy remembered-login cookies.
- Checks that the old SID no longer authenticates. A network failure or a still
  valid SID is not reported as success, even though browser cleanup still runs.

It retains unrelated desktop preferences, client-ID labels, and trusted-device
verification settings, as QTS's native logout does. It omits the desktop's
cosmetic wait mask, automatic redirect, and last-logout metadata update.
JavaScript cannot delete HttpOnly cookies, and clearing this context's session
storage does not clear session storage in separate tabs. Revoking the NAS session
is what ends authorization for other tabs/apps using that same session.

## Future application integration — not enabled in Koffan

The optional `qts-logout-helper.html` is a blank iframe wrapper. Install it next
to the JavaScript when ready:

```sh
curl -fL 'https://raw.githubusercontent.com/SupremeLobster/Koffan-qts/qnap-qts-auth/tools/qts-logout-helper/qts-logout-helper.html' -o /home/httpd/qts-logout-helper.html
chmod 644 /home/httpd/qts-logout-helper.html
```

Permit the application origin in QTS's iframe Allowed Websites settings. The
application loads `/qts-logout-helper.html` from the QTS origin, then sends:

```js
frame.contentWindow.postMessage({
  type: 'qts.logout', id: crypto.randomUUID()
}, 'https://shopping.mafucat.com:9443');
```

The response is `{ type: 'qts.logout.result', id, ...result }`. Only the configured
parent origins are accepted. The caller must check `event.origin`,
`event.source === frame.contentWindow`, matching ID, and `result.ok === true`.
A load event alone is not confirmation. Wait for completion before clearing the
application's own session and reopening its login iframe; clearing cookies first
can discard information QTS needs for remembered-client revocation.

The helper never sends SID, token, username, or client-ID values in a response.
No Koffan route, logout handler, deployment variable, or container build is
changed by adding these standalone files.
