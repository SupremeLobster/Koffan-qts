package handlers

import (
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"shopping-list/db"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

const qnapLogoutCookie = "koffan_qts_logout"

type qnapLogoutState struct {
	sid     string
	expires time.Time
}

// SID stays on the server. The browser receives only a random, short-lived
// operation ID. A separate cookie blocks silent SSO until logout is complete.
var pendingQNAPLogouts = struct {
	sync.Mutex
	states map[string]qnapLogoutState
}{states: make(map[string]qnapLogoutState)}

func getQNAPLogout(token string) (qnapLogoutState, bool) {
	pendingQNAPLogouts.Lock()
	defer pendingQNAPLogouts.Unlock()
	state, ok := pendingQNAPLogouts.states[token]
	if ok && time.Now().Before(state.expires) {
		return state, true
	}
	delete(pendingQNAPLogouts.states, token)
	return qnapLogoutState{}, false
}

func renderQNAPLogout(c *fiber.Ctx, token string, expired bool) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	c.Set("Referrer-Policy", "no-referrer")
	return c.Render("qnap-logout", fiber.Map{
		"LogoutToken": token, "QTSLogoutHelperURL": qnapAuth.logoutHelperURL, "LogoutExpired": expired,
	}, "")
}

func qnapLogout(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	if crossOriginRequest(c) {
		return c.SendStatus(fiber.StatusForbidden)
	}
	sid := strings.Clone(c.Cookies("NAS_SID"))
	previousToken := strings.Clone(c.Cookies(qnapLogoutCookie))
	if sid == "" {
		if previous, ok := getQNAPLogout(previousToken); ok {
			sid = previous.sid
		}
	}
	id := strings.Clone(c.Cookies(SessionCookieName))
	// Revoke app sessions/feeds immediately, but preserve QTS cookies and do
	// not call its logout API before the browser helper reads its credentials.
	if sid != "" {
		if err := db.DeleteQNAPSessions(qnapSIDHash(sid)); err != nil {
			log.Print("QTS logout: could not remove matching workspace sessions")
		}
	}
	if id != "" {
		if err := db.DeleteSession(id); err != nil {
			log.Print("QTS logout: could not remove browser workspace session")
		}
	}
	closeWebSockets(func(client *webSocketClient) bool {
		return (sid != "" && client.qnapSID == sid) || (id != "" && client.sessionID == id)
	})
	clearSessionCookie(c)
	token := generateSessionID()
	pendingQNAPLogouts.Lock()
	for key, state := range pendingQNAPLogouts.states {
		if time.Now().After(state.expires) {
			delete(pendingQNAPLogouts.states, key)
		}
	}
	delete(pendingQNAPLogouts.states, previousToken)
	if len(pendingQNAPLogouts.states) >= 1024 {
		pendingQNAPLogouts.Unlock()
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}
	pendingQNAPLogouts.states[token] = qnapLogoutState{sid: sid, expires: time.Now().Add(2 * time.Minute)}
	pendingQNAPLogouts.Unlock()
	c.Cookie(&fiber.Cookie{Name: qnapLogoutCookie, Value: token, Path: "/", HTTPOnly: true,
		Secure: isSecureConnection(c), SameSite: "Strict", SessionOnly: true})
	return renderQNAPLogout(c, token, false)
}

// QNAPLogoutComplete is called only after a matching successful helper reply.
// Independently verify the original SID before removing the pending-logout guard.
func QNAPLogoutComplete(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	if qnapAuth == nil {
		return c.SendStatus(fiber.StatusNotFound)
	}
	if crossOriginRequest(c) {
		return c.SendStatus(fiber.StatusForbidden)
	}
	token := strings.Clone(c.Cookies(qnapLogoutCookie))
	if len(token) != 64 || subtle.ConstantTimeCompare([]byte(token), []byte(c.Get("X-QTS-Logout-Token"))) != 1 {
		return c.SendStatus(fiber.StatusForbidden)
	}
	state, ok := getQNAPLogout(token)
	if !ok {
		return c.SendStatus(fiber.StatusConflict)
	}
	if state.sid != "" {
		_, err := qnapAuth.authenticate(state.sid)
		// A failed helper attempt clears browser storage too. On retry its
		// original SID may exist only in this server-side operation. End that
		// SID after helper cleanup, using QTS's native SID-in-query convention.
		if err == nil || errors.Is(err, errQNAPUser) {
			endpoint, _ := url.Parse(qnapAuth.apiURL)
			endpoint.Path = "/cgi-bin/authLogout.cgi"
			endpoint.RawQuery = url.Values{"sid": {state.sid}}.Encode()
			response, logoutErr := qnapAuth.client.PostForm(endpoint.String(), url.Values{"logout": {"1"}})
			if logoutErr != nil {
				return c.SendStatus(fiber.StatusServiceUnavailable)
			}
			_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			if response.StatusCode != http.StatusOK || readErr != nil {
				return c.SendStatus(fiber.StatusServiceUnavailable)
			}
			_, err = qnapAuth.authenticate(state.sid)
		}
		if !errors.Is(err, errQNAPSession) {
			if err == nil || errors.Is(err, errQNAPUser) {
				return c.SendStatus(fiber.StatusConflict)
			}
			return c.SendStatus(fiber.StatusServiceUnavailable)
		}
		if err := db.DeleteQNAPSessions(qnapSIDHash(state.sid)); err != nil {
			return c.SendStatus(fiber.StatusServiceUnavailable)
		}
	}
	clearQNAPBrowserCookies(c)
	pendingQNAPLogouts.Lock()
	delete(pendingQNAPLogouts.states, token)
	pendingQNAPLogouts.Unlock()
	return c.JSON(fiber.Map{"logged_out": true})
}

func clearQNAPBrowserCookies(c *fiber.Ctx) {
	// Clear both host-only and domain-scoped authentication cookies. QTS may
	// share its cookies with subdomains; a host-only deletion cannot remove those.
	domains := []string{""}
	host := c.Hostname()
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	if net.ParseIP(host) == nil && strings.Contains(host, ".") {
		for domain := host; strings.Contains(domain, "."); {
			domains = append(domains, domain)
			_, domain, _ = strings.Cut(domain, ".")
		}
	}
	// QTS's remember-login credentials are separate from NAS_SID. In
	// particular, deleting qtoken alone leaves older nas_1_a credentials and
	// the (intentionally misspelled by QTS) remeber flag available to login.html.
	names := map[string]bool{}
	for _, name := range []string{SessionCookieName, "NAS_SID", "NAS_USER",
		"qtoken", "qtoken_account", "remeber", "nas_1_a", "nas_1_u",
		"koffan_qts_sid", "koffan_qts_login_nonce"} {
		names[name] = true
	}
	// Also remove cookies supplied by this browser, including firmware-specific
	// names. Their values are neither logged nor copied into the response.
	c.Request().Header.VisitAllCookie(func(name, _ []byte) {
		names[string(name)] = true
	})
	for name := range names {
		for _, domain := range domains {
			// Path matching distinguishes /cgi-bin from /cgi-bin/ and login.html.
			// The latter cookies are not sent to Koffan's /logout endpoint.
			for _, path := range []string{"/", "/cgi-bin", "/cgi-bin/", "/cgi-bin/login.html"} {
				cookie := &http.Cookie{Name: name, Value: "", Path: path, Domain: domain,
					Expires: time.Unix(1, 0), MaxAge: -1, HttpOnly: true,
					Secure: isSecureConnection(c), SameSite: http.SameSiteLaxMode}
				// Fiber Cookie replaces earlier cookies with the same name,
				// dropping other paths/domains. Append each Set-Cookie separately.
				c.Response().Header.Add("Set-Cookie", cookie.String())
			}
		}
	}
	c.Cookie(&fiber.Cookie{Name: qnapLogoutCookie, Value: "", Path: "/", HTTPOnly: true,
		Secure: isSecureConnection(c), SameSite: "Strict", MaxAge: -1, Expires: time.Unix(1, 0)})
}
