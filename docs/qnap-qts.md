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
  real QTS login screen in an iframe and checks the session every three seconds.
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
- The Koffan logout button ends the QTS session through
  POST /cgi-bin/authLogout.cgi with logout=1 and the current SID. It verifies
  revocation through the authentication API before reporting success. This
  also ends access for other apps using that same QTS session; independent
  sessions on other devices are not logged out.
- Logout immediately revokes matching Koffan workspace sessions and live feeds,
  expires host-scoped NAS/session/remembered-login cookies, and clears Koffan's
  browser offline data. It stays on a signed-out page until Sign in again is
  clicked, avoiding an automatic login loop. If QTS cannot confirm logout, the
  page reports the failure and offers Retry sign out; the NAS cookie is kept
  for that explicit retry. No new environment variable is required.
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
| QNAP_URL | Required browser-facing QTS origin, including any non-default management port. |
| QNAP_API_URL | Optional origin reachable from the container; defaults to QNAP_URL. This never changes the browser login URL. |
| QNAP_ALLOWED_USERS | Optional comma-separated, case-sensitive usernames returned by QTS, e.g. alice,bob. Unset permits every authenticated QTS user to sign in to their own workspace. |
| QNAP_CA_CERT | Optional container path to a PEM CA certificate, added to system trust. |

QNAP_AUTH=true automatically enables multi-user workspace isolation, even if
MULTI_USER is unset or false. Setting MULTI_USER=true is also supported. Keep
DISABLE_AUTH unset or false. APP_PASSWORD is not needed for QTS accounts.
Invalid origins, malformed configuration and DISABLE_AUTH=true stop startup.
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
3. Click Koffan's logout button: confirm the signed-out page, then verify the
   NAS session no longer authorizes Koffan or QTS. Repeat logout after expiration.
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
