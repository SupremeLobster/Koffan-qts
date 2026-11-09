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

## Native QTS sign-in

Koffan now displays its own username/password form and talks to the QTS API
server-side. There is no embedded QTS page, iframe allowlist, or browser redirect
to the NAS login screen. Users with two-step verification enter the six-digit
TOTP security code from their authenticator. QR codes, push approvals, passkeys
and passwordless QTS login are not implemented by this native form.

The form posts to /auth/qts/login with a short-lived, same-origin login nonce.
Koffan sends the credentials to the configured NAS in a POST body, using the
QTS Base64 password format and force_to_check_2sv=1, including for localhost.
Base64 is not encryption: password requests require HTTPS to the NAS, except
for loopback development endpoints. Redirects are never followed and the
existing LOGIN_MAX_ATTEMPTS / LOGIN_WINDOW_MINUTES / LOGIN_LOCKOUT_MINUTES
limits also apply to native QTS password attempts.

Passwords and security codes are not stored in Koffan's database, cookies,
local storage, or logs. A completed login is revalidated with QTS to obtain the
canonical username and administrator flag. Incomplete MFA does not provision
accounts or issue an app session. Newly issued sessions are revoked if Koffan
denies access or cannot finish opening the account.

The NAS SID is kept in a host-only HttpOnly cookie named koffan_qts_sid, not
returned in JSON or exposed to JavaScript. The existing NAS_SID desktop cookie
is not overwritten. A Koffan workspace session still requires live validation
of the selected NAS identity on every request.

## Existing sessions and logout

If no API-created Koffan session has been selected, an existing NAS_SID cookie
sent by the browser is still reused automatically. Browsers share that cookie
only when its hostname, path, and security settings permit it. An expired
explicit Koffan API session is not silently replaced by a different desktop
account; the user sees the sign-in form again.

The logout button calls POST /cgi-bin/authLogout.cgi and verifies revocation
before reporting success. It ends the NAS session actually used by Koffan and
all matching Koffan workspace sessions/live feeds. If Koffan reused the desktop
NAS session, other apps using that same session are also signed out. If the
native form created a separate API session, independent QTS desktop/device
sessions and their cookies remain intact.

Logout clears Koffan's browser offline data and stays on a signed-out page
until Sign in again is clicked. The API credential is replaced by a non-secret
signed-out marker for the browser session, so another still-active QTS desktop
session cannot silently sign Koffan back in after an explicit logout. If QTS cannot confirm logout, an explicit retry
page appears and retains the selected NAS cookie for that retry.

## Network and theme setup

Keep your existing Koffan HTTPS reverse proxy, including its public hostname
(e.g. shopping2.mafucat.com). Native API sign-in does not require that hostname
to match the QTS hostname. Preserve Host and X-Forwarded-Proto, allow WebSocket
upgrades, and do not cache authenticated responses. HTTP is supported only on
loopback development connections for password sign-in.

The container must reach QTS's system administration HTTPS endpoint, not the
QNAP Web Server or Koffan's own port. Use the final HTTPS origin if Force HTTPS
is enabled, and a certificate trusted by the container. Each NAS request has a
five-second timeout. Login pages and notices follow the saved light/dark theme,
with system preference as the fallback; versioned assets avoid stale styling.

## Configuration

| Environment variable | Meaning |
| --- | --- |
| QNAP_AUTH=true | Enable QTS authentication. Unset or false retains existing authentication. |
| QNAP_URL | Required QTS origin, including any non-default management port; default API destination. |
| QNAP_API_URL | Optional QTS API origin reachable from the container; defaults to QNAP_URL. Must use HTTPS for password sign-in outside loopback. |
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
6. Configure the Koffan HTTPS proxy and an HTTPS QTS API connection. The old
   QTS iframe Allowed Websites entry is no longer needed for this native form.
   Test the browser address before replacing any existing shortcuts.

## NAS verification before using this build

This patch has not been verified on a live TS-431XeU/QTS device. Confirm the
installed firmware version in QTS; "latest" changes and is not a fixed version.

Check these cases using a private browser window and a non-admin household user:

1. Log in to QTS, open Koffan using the same hostname: no second login.
2. Sign out, open a Koffan list, and use the native username/password form.
   Confirm a TOTP-enabled account requires its security code before opening
   that list. Confirm incorrect codes and passwords stay on the form.
3. Click Koffan's logout button: confirm the signed-out page and that the NAS
   session used by Koffan is revoked. Repeat logout after expiration. Independent
   desktop sessions should remain active after native API-session logout.
   When testing a reused desktop session instead, signing it out directly in QTS
   must also reject Koffan writes and close its live feed. A denied user gets 403.
4. Stop access to the QTS API: Koffan receives 503 rather than granting access.
5. Sign in as two different normal QTS users: each starts with their own lists.
   Try another user's list URL and confirm access is refused. Share a workspace
   explicitly and confirm both members can access it.
6. Sign in as the QTS administrator: confirm admin privileges and access to the
   original Home workspace. Confirm existing shopping lists remain after restart.

Revoking a NAS session cannot remotely wipe a disconnected device. Koffan's
own logout clears offline shopping data in the current browser.

References:

- https://eu1.qnap.com/dev/QTS_HTTP_API-Authentication_v5.1.0.pdf
- https://docs.qnap.com/operating-system/qts/5.2.x/en-us/configuring-system-administration-settings-F6C72493.html
