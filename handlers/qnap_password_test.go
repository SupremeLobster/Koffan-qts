package handlers

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"shopping-list/db"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

func qnapPasswordTestApp(t *testing.T) *fiber.App {
	t.Helper()
	engine := html.New("", ".html")
	engine.Templates = template.New("qnap-pages").Funcs(template.FuncMap{
		"asset": func(path string) string { return "/static/" + path + "?v=test" },
	})
	for _, name := range []string{"qnap-login", "qnap-logout"} {
		source, err := os.ReadFile("../templates/" + name + ".html")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := engine.Templates.New(name).Parse(string(source)); err != nil {
			t.Fatal(err)
		}
	}
	engine.Loaded = true
	app := fiber.New(fiber.Config{Views: engine})
	app.Get("/login", LoginPage)
	app.Post("/auth/qts/login", QNAPLogin)
	app.Get("/auth/qts/status", QNAPAuthStatus)
	app.Post("/logout", Logout)
	app.Use(AuthMiddleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"user": CurrentUser(c), "workspace": WorkspaceID(c)})
	})
	return app
}

func qnapFormNonce(t *testing.T, app *fiber.App) string {
	t.Helper()
	page := authDo(t, app, "", "GET", "/login", nil, map[string]string{"X-Forwarded-Proto": "https"})
	if page.status != 200 || strings.Contains(page.body, "<iframe") || !strings.Contains(page.body, "autocomplete=\"current-password\"") {
		t.Fatalf("native sign-in form not rendered: %d %s", page.status, page.body)
	}
	for _, c := range (&http.Response{Header: page.header}).Cookies() {
		if c.Name == qnapLoginNonceCookie {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
				t.Fatal("login nonce cookie is not protected")
			}
			return c.Value
		}
	}
	t.Fatal("missing login nonce")
	return ""
}

func qnapSubmitPassword(t *testing.T, app *fiber.App, nonce, username, password, code string) authResult {
	t.Helper()
	return authDo(t, app, "", "POST", "/auth/qts/login",
		url.Values{"csrf": {nonce}, "username": {username}, "password": {password}, "security_code": {code}, "next": {"/lists/42"}},
		map[string]string{"Cookie": qnapLoginNonceCookie + "=" + nonce, "X-Forwarded-Proto": "https"})
}

func TestQNAPNativePasswordLoginUsesVerifiedIdentityAndPrivateCookie(t *testing.T) {
	const password = "Unicode pàssword & spaces"
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.RawQuery != "" {
			t.Error("credentials were placed in a URL")
		}
		if r.FormValue("pwd") != "" {
			if r.FormValue("pwd") != base64.StdEncoding.EncodeToString([]byte(password)) ||
				r.FormValue("force_to_check_2sv") != "1" || r.FormValue("serviceKey") != "1" || r.FormValue("remme") != "0" {
				t.Error("QTS credentials or forced two-step parameters are incorrect")
			}
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><authSid>api-private-sid</authSid><username>untrusted-form-identity</username></QDocRoot>")
		} else {
			if r.FormValue("sid") != "api-private-sid" {
				t.Error("wrong SID used for identity verification")
			}
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>admin</username><isAdmin>1</isAdmin></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	legacy := newGuardHousehold(t, "admin")
	app := qnapPasswordTestApp(t)
	nonce := qnapFormNonce(t, app)
	result := qnapSubmitPassword(t, app, nonce, "posted-name", password, "")
	if result.status != 200 || !strings.Contains(result.body, "\"authenticated\":true") ||
		strings.Contains(result.body, "api-private-sid") || strings.Contains(result.body, password) {
		t.Fatalf("password sign-in failed or leaked credentials: %d %s", result.status, result.body)
	}
	id, err := db.QNAPUserID("admin")
	if err != nil || id != legacy.user.ID {
		t.Fatal("verified QTS identity did not adopt its approved legacy account")
	}
	user, _ := db.GetUserByID(id)
	if !user.IsAdmin {
		t.Fatal("verified QTS admin role was ignored")
	}
	var privateCookie *http.Cookie
	for _, cookie := range (&http.Response{Header: result.header}).Cookies() {
		if cookie.Name == "NAS_SID" {
			t.Fatal("API login overwrote the desktop's NAS cookie")
		}
		if cookie.Name == qnapAPICookie {
			privateCookie = cookie
		}
	}
	if privateCookie == nil || privateCookie.Value != "api-private-sid" || !privateCookie.HttpOnly || !privateCookie.Secure {
		t.Fatal("NAS session was not stored in a protected Koffan-only cookie")
	}
	// The API cookie must take priority over a desktop login on the same host.
	page := authDo(t, app, "", "GET", "/", nil, map[string]string{
		"Cookie": qnapAPICookie + "=api-private-sid; NAS_SID=someone-else", "X-Forwarded-Proto": "https",
	})
	if page.status != 200 || !strings.Contains(page.body, "indexedDB.deleteDatabase") {
		t.Fatalf("native API login could not start a workspace: %d %s", page.status, page.body)
	}
}

func TestQNAPNativeLoginRequiresSecurityCodeAndDoesNotBypassMFA(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("pwd") == "" {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
		} else if r.FormValue("security_code") == "" {
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed><need_2sv>1</need_2sv></QDocRoot>")
		} else if r.FormValue("security_code") != "123456" {
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed><need_2sv>1</need_2sv></QDocRoot>")
		} else {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><need_2sv>1</need_2sv><authSid>mfa-sid</authSid></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapPasswordTestApp(t)
	nonce := qnapFormNonce(t, app)
	for _, tc := range []struct{ code, errorCode string }{
		{"", "security_code_required"}, {"000000", "invalid_credentials"},
	} {
		result := qnapSubmitPassword(t, app, nonce, "alice", "password", tc.code)
		if result.status != 401 || !strings.Contains(result.body, tc.errorCode) {
			t.Fatalf("incorrect MFA response: %d %s", result.status, result.body)
		}
		if result.header.Get("Set-Cookie") != "" || db.CountUsers() != 0 {
			t.Fatal("incomplete MFA established a session or account")
		}
	}
	result := qnapSubmitPassword(t, app, nonce, "alice", "password", "123456")
	if result.status != 200 {
		t.Fatalf("valid MFA rejected: %d %s", result.status, result.body)
	}
}

func TestQNAPNativeLoginRejectsCSRFAndRateLimitsFailures(t *testing.T) {
	var calls atomic.Int32
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapPasswordTestApp(t)
	nonce := qnapFormNonce(t, app)
	bad := authDo(t, app, "", "POST", "/auth/qts/login", url.Values{"csrf": {"wrong"}, "username": {"admin"}, "password": {"secret"}},
		map[string]string{"Cookie": qnapLoginNonceCookie + "=" + nonce, "X-Forwarded-Proto": "https"})
	if bad.status != 403 || calls.Load() != 0 {
		t.Fatal("invalid nonce reached the NAS")
	}
	bad = authDo(t, app, "", "POST", "/auth/qts/login", url.Values{"csrf": {nonce}, "username": {"admin"}, "password": {"secret"}},
		map[string]string{"Cookie": qnapLoginNonceCookie + "=" + nonce, "X-Forwarded-Proto": "https", "Origin": "https://evil.example"})
	if bad.status != 403 || calls.Load() != 0 {
		t.Fatal("cross-origin sign-in reached the NAS")
	}
	old := loginLimiter
	loginLimiter = &LoginRateLimiter{config: RateLimitConfig{MaxAttempts: 1, WindowDuration: time.Minute, LockoutDuration: time.Minute}, attempts: map[string]*LoginAttempt{}}
	t.Cleanup(func() { loginLimiter = old })
	for i := 0; i < 3; i++ {
		_ = qnapSubmitPassword(t, app, nonce, "admin", "wrong", "")
	}
	if calls.Load() != 2 {
		t.Fatalf("blocked password attempts reached QTS: %d", calls.Load())
	}
}

func TestQNAPPasswordLoginRejectsInsecureNASAndMalformedReplies(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"missing flag", "<QDocRoot/>", 200},
		{"missing SID", "<QDocRoot><authPassed>1</authPassed></QDocRoot>", 200},
		{"wrong root", "<html><authPassed>1</authPassed><authSid>sid</authSid></html>", 200},
		{"HTTP error", "", 503}, {"redirect", "", 307},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) })
			if sid, err := auth.passwordSession("user", "secret", ""); err == nil || sid != "" {
				t.Fatal("malformed authentication was accepted")
			}
		})
	}
	auth := qnapTestAuth(t, func(http.ResponseWriter, *http.Request) { t.Error("insecure credentials sent to NAS") })
	auth.apiURL = "http://nas.example/cgi-bin/authLogin.cgi"
	if _, err := auth.passwordSession("user", "secret", ""); err != errQNAPCredentialHTTPS {
		t.Fatalf("HTTP NAS password request allowed: %v", err)
	}
}

func TestQNAPAPISessionLogoutPreservesIndependentDesktopSession(t *testing.T) {
	var revoked atomic.Bool
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/authLogout.cgi" {
			if r.FormValue("sid") != "private-api-sid" {
				t.Error("logout targeted the desktop session")
			}
			revoked.Store(true)
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else {
			if !revoked.Load() {
				t.Error("logout was not performed before revocation check")
			}
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	result := authDo(t, qnapPasswordTestApp(t), "", "POST", "/logout", nil, map[string]string{"Cookie": qnapAPICookie + "=private-api-sid; NAS_SID=independent-desktop"})
	if result.status != 200 {
		t.Fatalf("API session logout failed: %d %s", result.status, result.body)
	}
	cleared := false
	for _, cookie := range (&http.Response{Header: result.header}).Cookies() {
		if cookie.Name == "NAS_SID" || cookie.Name == "qtoken" {
			t.Fatal("independent desktop credentials were cleared")
		}
		if cookie.Name == qnapAPICookie && cookie.Value == qnapLoggedOutSID {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("API session cookie survived logout")
	}
	probe := authDo(t, qnapPasswordTestApp(t), "", "GET", "/auth/qts/status", nil, map[string]string{
		"Cookie": qnapAPICookie + "=" + qnapLoggedOutSID + "; NAS_SID=independent-desktop",
	})
	if probe.status != 401 {
		t.Fatal("explicit logout silently reused a desktop session")
	}
}

func TestQNAPNativeLoginDoesNotAcceptAPartialMFASession(t *testing.T) {
	var revoked atomic.Bool
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/authLogout.cgi" {
			revoked.Store(true)
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else if r.FormValue("pwd") != "" {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><need_2sv>1</need_2sv><authSid>partial-session</authSid></QDocRoot>")
		} else {
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapPasswordTestApp(t)
	result := qnapSubmitPassword(t, app, qnapFormNonce(t, app), "alice", "password", "")
	if result.status != 401 || !strings.Contains(result.body, "security_code_required") || !revoked.Load() ||
		db.CountUsers() != 0 || result.header.Get("Set-Cookie") != "" {
		t.Fatalf("incomplete MFA created access: %d %s", result.status, result.body)
	}
}

func TestQNAPNativeLoginRevokesDeniedAccountSession(t *testing.T) {
	var revoked atomic.Bool
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/authLogout.cgi" {
			revoked.Store(true)
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else if r.FormValue("pwd") != "" {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><authSid>denied-session</authSid></QDocRoot>")
		} else if revoked.Load() {
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>denied-user</username></QDocRoot>")
		}
	})
	auth.allowedUsers = map[string]bool{"allowed-user": true}
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapPasswordTestApp(t)
	result := qnapSubmitPassword(t, app, qnapFormNonce(t, app), "denied-user", "password", "")
	if result.status != 403 || !revoked.Load() || db.CountUsers() != 0 || result.header.Get("Set-Cookie") != "" {
		t.Fatalf("denied QTS account gained access or retained a new session: %d %s", result.status, result.body)
	}
}
