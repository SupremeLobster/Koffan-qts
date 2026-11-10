package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"shopping-list/db"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

func qnapLogoutTestApp(t *testing.T) *fiber.App {
	t.Helper()
	source, err := os.ReadFile("../templates/qnap-logout.html")
	if err != nil {
		t.Fatal(err)
	}
	engine := html.New("", ".html")
	engine.Templates, err = template.New("qnap-logout").Funcs(template.FuncMap{
		"asset": func(path string) string { return "/static/" + path + "?v=test" },
	}).Parse(string(source))
	if err != nil {
		t.Fatal(err)
	}
	engine.Loaded = true
	app := fiber.New(fiber.Config{Views: engine})
	app.Post("/logout", Logout)
	app.Post("/auth/qts/logout/complete", QNAPLogoutComplete)
	app.Get("/login", LoginPage)
	app.Get("/auth/qts/status", QNAPAuthStatus)
	app.Use(AuthMiddleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"user": CurrentUser(c), "workspace": WorkspaceID(c)})
	})
	return app
}

func pendingLogoutToken(t *testing.T, response authResult) string {
	t.Helper()
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Name == qnapLogoutCookie && cookie.Value != "" {
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("pending cookie is not protected")
			}
			return cookie.Value
		}
	}
	t.Fatal("missing pending logout cookie")
	return ""
}

func finishQNAPLogout(t *testing.T, app *fiber.App, token string) authResult {
	t.Helper()
	return authDo(t, app, "", "POST", "/auth/qts/logout/complete", nil, map[string]string{
		"Cookie": qnapLogoutCookie + "=" + token, "X-QTS-Logout-Token": token,
	})
}

func TestQNAPLogoutPreservesNASCredentialsUntilHelperCompletes(t *testing.T) {
	var revoked atomic.Bool
	var serverLogoutCalls atomic.Int32
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/authLogout.cgi" {
			serverLogoutCalls.Add(1)
			t.Error("server logged out before the browser helper")
		}
		if revoked.Load() && r.FormValue("sid") == "alice" {
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	useFakeSockets(t)
	app := qnapLogoutTestApp(t)
	first, second, other := qnapSignIn(t, app, "alice"), qnapSignIn(t, app, "alice"), qnapSignIn(t, app, "other-device")
	socket := connectFakeSocket(first.workspace, first.user.ID, first.cookie, time.Now().Add(time.Hour).Unix())
	socket.client.qnapSID = first.sid
	otherSocket := connectFakeSocket(other.workspace, other.user.ID, other.cookie, time.Now().Add(time.Hour).Unix())
	otherSocket.client.qnapSID = other.sid
	response := qnapAccountRequest(t, app, first.sid, first.cookie, "POST", "/logout", nil, nil)
	token := pendingLogoutToken(t, response)
	if response.status != 200 || !strings.Contains(response.body, auth.logoutHelperURL) || strings.Contains(response.body, "alice") {
		t.Fatalf("missing helper configuration or exposed SID: %d %s", response.status, response.body)
	}
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Name == "NAS_SID" || cookie.Name == "qtoken" || cookie.Name == "NAS_USER" {
			t.Fatal("NAS credentials deleted before helper could read them")
		}
	}
	for _, id := range []string{first.cookie, second.cookie} {
		if _, err := db.GetSession(id); err == nil {
			t.Fatal("matching local session survived")
		}
	}
	if _, err := db.GetSession(other.cookie); err != nil {
		t.Fatal("unrelated session was removed")
	}
	if !socket.closed() || otherSocket.closed() {
		t.Fatal("wrong live feeds were closed")
	}
	headers := map[string]string{"Cookie": "NAS_SID=alice; " + qnapLogoutCookie + "=" + token}
	if got := authDo(t, app, "", "GET", "/", nil, headers); got.status != 302 {
		t.Fatal("pending browser silently reauthenticated")
	}
	if got := authDo(t, app, "", "GET", "/auth/qts/status", nil, headers); got.status != 401 {
		t.Fatal("pending session status accepted")
	}
	if got := authDo(t, app, "", "GET", "/login", nil, headers); !strings.Contains(got.body, "qnap-logout.js") {
		t.Fatal("reload did not resume helper cleanup")
	}
	revoked.Store(true) // The browser helper has now revoked the NAS session.
	finished := finishQNAPLogout(t, app, token)
	if finished.status != 200 || !strings.Contains(finished.body, `"logged_out":true`) {
		t.Fatalf("finish failed: %d %s", finished.status, finished.body)
	}
	cleared := map[string]bool{}
	for _, cookie := range (&http.Response{Header: finished.header}).Cookies() {
		if cookie.MaxAge < 0 && cookie.Path == "/" {
			cleared[cookie.Name] = true
		}
	}
	for _, name := range []string{SessionCookieName, qnapLogoutCookie, "NAS_SID", "qtoken", "remeber"} {
		if !cleared[name] {
			t.Errorf("%s not cleared", name)
		}
	}
	if serverLogoutCalls.Load() != 0 {
		t.Fatal("duplicate server logout")
	}
	if replay := finishQNAPLogout(t, app, token); replay.status != 409 {
		t.Fatal("completion token was reusable")
	}
}

func TestQNAPLogoutCompletionRequiresCSRFTokenAndLiveOperation(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapLogoutTestApp(t)
	start := qnapAccountRequest(t, app, "", "", "POST", "/logout", nil, nil)
	token := pendingLogoutToken(t, start)
	for _, headers := range []map[string]string{
		{"Cookie": qnapLogoutCookie + "=" + token},
		{"X-QTS-Logout-Token": token},
		{"Cookie": qnapLogoutCookie + "=" + token, "X-QTS-Logout-Token": strings.Repeat("0", 64)},
		{"Cookie": qnapLogoutCookie + "=" + token, "X-QTS-Logout-Token": token, "Origin": "https://evil.example"},
	} {
		result := authDo(t, app, "", "POST", "/auth/qts/logout/complete", nil, headers)
		if result.status != 403 || result.header.Get("Set-Cookie") != "" {
			t.Fatal("unsafe completion accepted")
		}
	}
	pendingQNAPLogouts.Lock()
	state := pendingQNAPLogouts.states[token]
	state.expires = time.Now().Add(-time.Second)
	pendingQNAPLogouts.states[token] = state
	pendingQNAPLogouts.Unlock()
	if got := finishQNAPLogout(t, app, token); got.status != 409 {
		t.Fatal("expired operation accepted")
	}
	resumed := authDo(t, app, "", "GET", "/login", nil, map[string]string{"Cookie": qnapLogoutCookie + "=" + token})
	if !strings.Contains(resumed.body, `data-expired="true"`) {
		t.Fatal("expired operation silently reopened login")
	}
}

func TestQNAPLogoutRejectsCrossOriginRequests(t *testing.T) {
	auth := qnapTestAuth(t, func(http.ResponseWriter, *http.Request) { t.Error("cross-origin logout contacted QTS") })
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	result := qnapAccountRequest(t, qnapLogoutTestApp(t), "secret", "", "POST", "/logout", nil, map[string]string{"Origin": "https://evil.example"})
	if result.status != 403 || result.header.Get("Set-Cookie") != "" {
		t.Fatal("cross-origin logout caused side effects")
	}
}

func TestQNAPLogoutCompletionOutageKeepsPendingGuard(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapLogoutTestApp(t)
	token := pendingLogoutToken(t, qnapAccountRequest(t, app, "secret", "", "POST", "/logout", nil, nil))
	result := finishQNAPLogout(t, app, token)
	if result.status != 503 || result.header.Get("Set-Cookie") != "" {
		t.Fatal("outage removed pending guard")
	}
	if _, ok := getQNAPLogout(token); !ok {
		t.Fatal("retry state was discarded")
	}
}

func TestQNAPLogoutClearsCookiePathsAndDomains(t *testing.T) {
	auth := qnapTestAuth(t, func(http.ResponseWriter, *http.Request) { t.Error("no SID should be sent to QTS") })
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapLogoutTestApp(t)
	token := pendingLogoutToken(t, authDo(t, app, "", "POST", "http://shopping.mafucat.com:8443/logout", nil, nil))
	response := authDo(t, app, "", "POST", "http://shopping.mafucat.com:8443/auth/qts/logout/complete", nil, map[string]string{
		"Cookie": qnapLogoutCookie + "=" + token + "; nas_2_a=private-remembered-credential; firmware_remember=private-token", "X-QTS-Logout-Token": token,
	})
	if response.status != 200 {
		t.Fatalf("completion failed: %d", response.status)
	}
	cleared := map[string]bool{}
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if strings.Contains(cookie.Value, "private-") {
			t.Fatal("cookie value exposed")
		}
		if cookie.MaxAge < 0 {
			cleared[cookie.Name+"|"+cookie.Domain+"|"+cookie.Path] = true
		}
	}
	for _, name := range []string{SessionCookieName, "NAS_SID", "NAS_USER", "qtoken", "qtoken_account", "remeber", "nas_1_a", "nas_1_u", "nas_2_a", "firmware_remember"} {
		for _, domain := range []string{"", "shopping.mafucat.com", "mafucat.com"} {
			for _, path := range []string{"/", "/cgi-bin", "/cgi-bin/", "/cgi-bin/login.html"} {
				if !cleared[name+"|"+domain+"|"+path] {
					t.Errorf("cookie not cleared: %s %s %s", name, domain, path)
				}
			}
		}
	}
}

func TestQNAPLogoutRetryCanEndSIDAfterHelperClearedBrowserStorage(t *testing.T) {
	var revoked atomic.Bool
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/authLogout.cgi" {
			if r.URL.Query().Get("sid") != "original" || r.FormValue("logout") != "1" {
				t.Error("retry did not use native logout parameters")
			}
			revoked.Store(true)
		}
		if revoked.Load() {
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapLogoutTestApp(t)
	token := pendingLogoutToken(t, qnapAccountRequest(t, app, "original", "", "POST", "/logout", nil, nil))
	// No NAS cookie remains after a failed helper attempt; a retry preserves SID server-side.
	retry := authDo(t, app, "", "POST", "/logout", nil, map[string]string{"Cookie": qnapLogoutCookie + "=" + token})
	newToken := pendingLogoutToken(t, retry)
	finished := finishQNAPLogout(t, app, newToken)
	if finished.status != 200 || !revoked.Load() {
		t.Fatal("retry did not revoke the retained SID")
	}
}

func TestQNAPLogoutCannotCompleteWhileSIDRemainsValid(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapLogoutTestApp(t)
	token := pendingLogoutToken(t, qnapAccountRequest(t, app, "active", "", "POST", "/logout", nil, nil))
	if got := finishQNAPLogout(t, app, token); got.status != 409 {
		t.Fatal("active SID accepted after unsuccessful server cleanup")
	}
}
