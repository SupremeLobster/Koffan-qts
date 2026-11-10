# QNAP QTS session authentication in Container Station

QNAP_AUTH=true uses QTS login with Koffan's multi-user workspaces. Each QTS
username is provisioned as a distinct Koffan account at first sign-in, with a
private workspace. Users see another person's lists only after that workspace
is explicitly shared with them.

The QTS authentication API's isAdmin flag determines Koffan administrator
privileges, including for the NAS account named admin. This role is refreshed
on every authenticated request; browser cookies cannot supply an admin flag.
As in native MULTI_USER mode, administrators can manage workspace membership.
They are not automatically made members of every workspace.

On upgrade, existing lists remain in the original Home workspace. If that
workspace has no members, its ownership is assigned to the first QTS
administrator who signs in. Non-administrators never inherit the old lists.
If it already has members, the existing ownership is preserved.

Accounts/passwords are managed in QTS, not in Koffan. Accounts appear in Koffan's
administration list after their first sign-in and can then be added to shared
workspaces. The approved legacy accounts admin, marti.mas and nurieta are
adopted automatically after QTS verifies the exact matching username. Adoption
preserves the existing account ID, display name, workspace memberships, lists,
items and history. It disables the old local password, revokes old Koffan
sessions, and synchronizes administrator privileges from QTS. No replacement
workspace is created. Subsequent logins reuse the same linked account.

Other pre-existing local usernames, case-different matches, and accounts already
linked to a different QTS identity still produce an explicit conflict. No
additional environment variable or manual database edit is needed for the three
approved migrations. Back up shopping.db before deploying the update.

## Login behavior and the QTS limitation

- An existing NAS_SID cookie is checked server-side against QTS before Koffan
  serves protected pages, writes, or accepts a WebSocket.
- Without a valid session, Koffan opens its QTS sign-in page. This displays the
  real QTS login screen in a full-page iframe and checks the session every three seconds.
  Help text is hidden during normal sign-in and appears for detected loading,
  configuration, or authentication-service problems. Browser restrictions mean
  cross-origin frame failures cannot always be detected; opening QTS directly
  in another tab remains a fallback if the browser shows its own blocked-frame page.
  After QTS login (including QTS MFA), Koffan automatically opens the originally
  requested page.
- This is an embedded QTS login flow, not a top-level QTS redirect with an OAuth
  callback. No documented general-purpose third-party callback was found in the
  QTS authentication API. Do not invent a return_url parameter on login.html.
- QTS blocks embedding by default. Add only Koffan's exact public origin to QTS's
  **Allowed Websites** under the system administration iframe settings. Keep
  protection enabled for other websites. If embedding remains blocked, use the
  provided **open QTS in another tab** link, log in, then return to the Koffan tab;
  that tab detects the session and opens the app.
- The Koffan logout button revokes its workspace sessions and live feeds, then
  loads the shared NAS helper in a hidden iframe **before** clearing QTS cookies.
  The helper runs on the QTS origin, sends QTS's native remembered-client logout
  parameters, and removes QTS's stored SID and remembered-login token. It replies
  only to an explicitly allowed parent application origin.
- Koffan checks the reply's origin, window, operation ID and success fields, then
  independently confirms the original SID is revoked through QNAP_API_URL. If a
  failed previous attempt cleared the browser SID, Koffan can revoke its retained
  server-side SID after helper cleanup. It then expires browser cookies, clears
  private offline data and returns automatically to /, which opens login.
- Successful logout has no result screen. A missing/blocked helper, failed
  cleanup, NAS outage or unverified revocation shows a theme-aware Retry sign out
  message. A pending-logout cookie blocks silent SSO during failure and after a
  reload. Pending operation details expire after two minutes; retry creates a new
  attempt. JavaScript is required; disabling it does not silently reopen login.
- Signing out directly in QTS also rejects subsequent Koffan requests. In that
  case, existing Koffan live feeds close within 30 seconds plus the five-second
  NAS request timeout.

QTS notices and the standalone login/logout pages follow Koffan's saved light
or dark theme, falling back to the system preference. Authentication assets use
versioned URLs so updated colors are loaded after a rebuild.

## Required browser and network layout

Use exactly the same hostname (or NAS IP) and protocol for QTS and Koffan.
Different ports are supported. For example:

| Purpose | Example |
| --- | --- |
| QTS in the browser, QNAP_URL | https://nas.example |
| Koffan in the browser | https://nas.example:8443 |
| Koffan container mapping | NAS port 3000 to container port 8080 |
| HTTPS reverse proxy | NAS port 8443 to http://127.0.0.1:3000 |

Configure HTTPS termination for the Koffan port using the NAS reverse proxy or
your existing proxy. Preserve Host and X-Forwarded-Proto, allow WebSocket upgrades,
and do not cache authenticated responses. Open Koffan at its HTTPS address.
Host-only QTS cookies do not transfer to koffan.example or to a container's IP.
An HTTPS Secure cookie will not transfer to an HTTP Koffan URL.

This layout requires QTS to issue NAS_SID with a cookie path that includes Koffan
(normally /). If your firmware or proxy scopes it to /cgi-bin or keeps the
session only in browser storage, a NAS-side bridge is required; this patch alone
cannot bypass browser cookie boundaries. Never paste a SID into an app URL.

The container must reach QTS's system administration API, not the QNAP Web Server
or Koffan's own port. It uses POST /cgi-bin/authLogin.cgi with the SID in the body.
Requests time out in five seconds and never follow redirects. Use QTS's final
HTTPS origin if Force HTTPS is enabled.

## Configuration

| Environment variable | Meaning |
| --- | --- |
| QNAP_AUTH=true | Enable QTS authentication. Unset or false retains existing authentication. |
| QNAP_URL | Browser-facing QTS origin, including any non-default management port. Defaults to QNAP_API_URL when unset. |
| QNAP_API_URL | API origin reachable from the container; defaults to QNAP_URL. When QNAP_URL is explicitly set, this does not change the browser login URL. |
| QNAP_LOGOUT_HELPER_URL | Optional helper page on exactly the QNAP_URL origin. Defaults to QNAP_URL + /qts-logout-helper.html. |
| QNAP_ALLOWED_USERS | Optional comma-separated, case-sensitive usernames returned by QTS, e.g. alice,bob. Unset permits every authenticated QTS user to sign in to their own workspace. |
| QNAP_CA_CERT | Optional container path to a PEM CA certificate, added to system trust. |

QNAP_AUTH=true automatically enables multi-user workspace isolation, even if
MULTI_USER is unset or false. Setting MULTI_USER=true is also supported. Keep
DISABLE_AUTH unset or false. APP_PASSWORD is not needed for QTS accounts.
Set at least one of QNAP_URL or QNAP_API_URL. If only QNAP_API_URL is set, its
origin must also be reachable by the browser and satisfy the shared-hostname
cookie requirements above. Set both when the container uses a different API
address. Invalid origins, malformed configuration and DISABLE_AUTH=true stop startup.
A Koffan session cookie remembers workspace selection, but it cannot authorize
access without the same live QTS identity and NAS session. Old shared-password
sessions are rejected. Switching QTS identities clears the previous workspace's
offline cache, revokes the old browser session, and rejects stale writes. The existing
token-authenticated /api/v1 REST API remains separate; configure or disable its
API_TOKEN as appropriate for your existing integrations.

Use a certificate trusted by the container, with QNAP_URL/QNAP_API_URL's hostname
in its SANs. For a private CA, mount its certificate read-only and set
QNAP_CA_CERT to that path. TLS verification is never disabled. For example, add:

    environment:
      QNAP_CA_CERT: /certs/nas-ca.pem
    volumes:
      - /share/Container/certs/nas-ca.pem:/certs/nas-ca.pem:ro

Authentication failures return a login prompt; denied accounts receive 403.
Unavailable QTS or malformed responses receive 503 and cannot fall back to the
shared password. No successful-authentication cache extends an expired session.

## Offline shopping with QTS authentication

After a successful online sign-in and initial load, the shopping UI and its
IndexedDB model remain usable offline, including creating/editing/deleting
lists, sections and items. Changes queue locally and synchronize when the NAS
is reachable again and the same account has a valid QTS session.

Shopping documents explicitly opt in to the service worker's private device
cache using `X-Koffan-Offline: shopping-v1`. They still send `Cache-Control:
private, no-store` to prevent HTTP/proxy caching. Login/logout pages, session
probes, API results and HTMX fragments do not use that offline document cache.
The generic list shell is also restored after an account/workspace cache reset.

Transport failures and temporary NAS/server errors can use the saved shopping
UI. Definite authentication failures and login redirects still require online
sign-in before uploading anything. Queued edits survive reauthentication and a
renewed NAS SID for the same user/workspace; an account/workspace change or
explicit logout still clears the previous private offline copy. Offline use is
access to the previously downloaded local data, not a bypass of server-side QTS
authentication. Every online sync request still validates its QTS identity and
workspace membership.

After deploying this fix, open Koffan online once and let the service worker
finish preparing its files before testing offline. The earlier QTS builds
refused to cache their shopping documents, so those missing copies cannot be
recovered until that initial online visit.

## Install the NAS logout helper

The JavaScript helper must be installed on the QTS management web server and
configured for the browser-facing QTS origin and the exact Koffan public origin.
For the tested setup, its defaults are QTS `https://shopping.mafucat.com:9443` and
Koffan `https://shopping.mafucat.com`. Other deployments must edit those constants.
See [the standalone helper instructions](../tools/qts-logout-helper/README.md).

If the JavaScript helper is already installed and tested, add its blank HTML
wrapper over SSH with permission to write QTS's web root:

```sh
curl -fL 'https://raw.githubusercontent.com/SupremeLobster/Koffan-qts/qnap-qts-auth/tools/qts-logout-helper/qts-logout-helper.html' -o /home/httpd/qts-logout-helper.html
chmod 644 /home/httpd/qts-logout-helper.html
```

Verify that `https://shopping.mafucat.com:9443/qts-logout-helper.html` serves the
blank wrapper and that its JavaScript loads. Keep Koffan's exact public origin
in QTS's iframe Allowed Websites settings; the logout helper needs embedding
permission just like the login screen. There is no redirect or storage cleanup
merely from opening the wrapper.

Set QNAP_URL to the actual QTS browser origin, including :9443 in this setup.
QNAP_API_URL may continue to use a different container-reachable NAS address.
No new environment variable is needed for the default helper path. Firmware
updates or NAS reboots may require reinstalling the helper files.

## Build and install

Use the current QTS integration branch of SupremeLobster/Koffan-qts. Earlier
QTS bundles only gated the shared workspace; they do not include this account
isolation update. Back up shopping.db before deploying the new build.

1. Back up the existing shopping.db database and record its existing bind mount
   or volume name. Stop the current Koffan container before replacing it.
2. Check out the updated integration source, preserving your Dockerfile.qnap32k
   if it was created locally. Do not revert to the original shared-workspace
   integration bundle.
3. Run the checks from the full patched source:

       gofmt -w handlers/qnap.go handlers/qnap_test.go
       go test ./...
       node test/qnap-login.test.js
       node --test test/*.test.js

4. Build on your computer using the included native cross-compiler Dockerfile.
   The TS-431XeU needs both ARMv7 and 32 KiB ELF alignment. The final image is
   static and uses scratch, avoiding an incompatible runtime userland:

       docker buildx build --platform linux/arm/v7 -f Dockerfile.qnap32k --load -t koffan:qts .
       docker save -o koffan-qts-armv7.tar koffan:qts

   Transfer the image archive to the NAS and import it into Container Station
   (or use docker load -i koffan-qts-armv7.tar over SSH). This is a custom build;
   pulling the upstream latest image does not include this patch.
5. Create the container/application using docker-compose.qnap.yaml. Set QNAP_URL
   to your actual QTS origin and QNAP_ALLOWED_USERS to your household users.
   Replace the example volume with your existing Koffan storage mount. The
   example creates a new named volume unless you explicitly reuse the old one.
6. Configure the HTTPS proxy and QTS iframe Allowed Websites setting above.
   Test the browser addresses before replacing any existing shortcuts.

## NAS verification before using this build

This patch has not been verified on a live TS-431XeU/QTS device. Confirm the
installed firmware version in QTS; "latest" changes and is not a fixed version.

Check these cases using a private browser window and a non-admin household user:

1. Log in to QTS, open Koffan using the same hostname: no second login.
2. Clear/sign out of QTS and open a Koffan list: the actual QTS login screen
   appears; after login/MFA, that list opens automatically.
3. Sign in with QTS “Keep me logged in” enabled, then click Koffan's logout
   button. Confirm the iframe returns to an unauthenticated login screen and
   stays there after a reload, without automatically signing in again. Verify
   the NAS session no longer authorizes Koffan or QTS. Repeat without the
   remember-login option and after session expiration.
   Also sign out of QTS in another tab: Koffan writes must be rejected and its live
   feed must close. A removed/denied username receives 403.
4. Stop access to the QTS API: Koffan receives 503 rather than granting access.
5. Sign in as two different normal QTS users: each starts with their own lists.
   Try another user's list URL and confirm access is refused. Share a workspace
   explicitly and confirm both members can access it.
6. Sign in as the QTS administrator: confirm admin privileges and access to the
   original Home workspace. Confirm existing shopping lists remain after restart.

QTS auth does not erase already saved offline shopping data on a device.

References:

- https://eu1.qnap.com/dev/QTS_HTTP_API-Authentication_v5.1.0.pdf
- https://docs.qnap.com/operating-system/qts/5.2.x/en-us/configuring-system-administration-settings-F6C72493.html
