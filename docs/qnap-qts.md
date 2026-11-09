# QNAP QTS session authentication in Container Station

This opt-in integration replaces Koffan's shared password with a validated QTS
session. Eligible NAS users share Koffan's existing default shopping workspace.
It does not create Koffan accounts, copy NAS passwords, or elevate users to NAS
administrators. Local MULTI_USER accounts cannot be combined with this mode.

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
- Signing out of QTS rejects subsequent Koffan requests immediately. Live feeds
  close within 30 seconds plus the five-second NAS request timeout. The Koffan
  sign-out page explains how to sign out of QTS without silently ending NAS
  sessions used by other apps.

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
| QNAP_ALLOWED_USERS | Optional comma-separated, case-sensitive usernames returned by QTS, e.g. alice,bob. Unset allows every authenticated QTS user into the shared shopping workspace. |
| QNAP_CA_CERT | Optional container path to a PEM CA certificate, added to system trust. |

Set MULTI_USER and DISABLE_AUTH to false or leave them unset. Conflicting modes,
invalid origins and malformed configuration stop startup. APP_PASSWORD and old
Koffan session cookies do not authenticate requests in QTS mode. The existing
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

The downloadable patch targets upstream PanSalut/Koffan commit
b5eefc90743d1a478bfad8b4be7740912e3995f7. The accompanying install.sh clones that
revision and applies the patch. It does not deploy or alter NAS data.

1. Back up the existing shopping.db database and record its existing bind mount
   or volume name. Stop the current Koffan container before replacing it.
2. Apply the patch to the pinned upstream source using the installer, or use
   git apply --check followed by git apply in your own checkout.
3. Run the checks from the full patched source:

       gofmt -w handlers/qnap.go handlers/qnap_test.go
       go test ./...
       node test/qnap-login.test.js
       node --test test/*.test.js

4. Build a custom image. The TS-431XeU uses 32-bit ARM; on a buildx builder
   configured for ARMv7 builds (native or with emulation):

       docker buildx build --platform linux/arm/v7 --load -t koffan:qts .
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
3. Sign out of QTS in another tab: Koffan writes are rejected and its live feed
   closes. A removed/denied username receives 403.
4. Stop access to the QTS API: Koffan receives 503 rather than granting access.
5. Confirm the existing shopping lists remain after restart.

QTS auth does not erase already saved offline shopping data on a device.

References:

- https://eu1.qnap.com/dev/QTS_HTTP_API-Authentication_v5.1.0.pdf
- https://docs.qnap.com/operating-system/qts/5.2.x/en-us/configuring-system-administration-settings-F6C72493.html
