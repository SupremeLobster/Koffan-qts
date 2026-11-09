package handlers

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func qnapTestAuth(t *testing.T, upstream http.HandlerFunc) *qnapAuthenticator {
	t.Helper()
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)
	t.Setenv("QNAP_AUTH", "true")
	t.Setenv("QNAP_URL", server.URL)
	t.Setenv("QNAP_API_URL", "")
	t.Setenv("QNAP_CA_CERT", "")
	t.Setenv("QNAP_ALLOWED_USERS", "")
	t.Setenv("MULTI_USER", "false")
	t.Setenv("DISABLE_AUTH", "false")
	auth, err := qnapAuthFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func qnapUseTestAuth(t *testing.T, auth *qnapAuthenticator) {
	t.Helper()
	old := qnapAuth
	qnapAuth = auth
	t.Cleanup(func() { qnapAuth = old })
}

func TestQNAPValidatesOnEveryRequest(t *testing.T) {
	var valid atomic.Bool
	valid.Store(true)
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/cgi-bin/authLogin.cgi" || r.URL.RawQuery != "" {
			t.Errorf("unexpected QTS request: %s %s", r.Method, r.URL)
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("sid") != "existing-sid" {
			t.Error("SID missing from POST body")
		}
		if valid.Load() {
			io.WriteString(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
		} else {
			io.WriteString(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := fiber.New()
	app.Use(AuthMiddleware)
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("shopping list") })
	localCookie := "old-koffan-cookie"
	request := func() *http.Response {
		t.Helper()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Cookie", "NAS_SID=existing-sid; NAS_USER=forged-admin; session="+localCookie)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := request()
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("valid session: %d", resp.StatusCode)
	}
	if len(resp.Cookies()) != 1 {
		t.Fatal("missing bound workspace session")
	}
	localCookie = resp.Cookies()[0].Value
	resp = request()
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "shopping list" {
		t.Fatalf("workspace session not accepted: %s", data)
	}
	valid.Store(false)
	resp = request()
	defer resp.Body.Close()
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Fatalf("revoked QTS session still authorized: %d", resp.StatusCode)
	}
	if socketStillAllowed(&webSocketClient{qnapSID: "existing-sid"}) {
		t.Fatal("revoked QTS session still authorizes the live feed")
	}
}

func TestQNAPRejectsUntrustedCredentialsAndCrossOriginWrites(t *testing.T) {
	var calls atomic.Int64
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
	})
	qnapUseTestAuth(t, auth)
	app := fiber.New()
	app.Post("/login", Login)
	app.Use(AuthMiddleware)
	app.All("/*", func(c *fiber.Ctx) error { return c.SendStatus(200) })
	for _, tc := range []struct {
		method, path, cookie, origin string
		status                       int
	}{
		{"GET", "/?sid=forged", "session=legacy; NAS_USER=admin; qtoken=forged", "", 302},
		{"GET", "/api/offline/snapshot", "", "", 401},
		{"GET", "/ws", "", "", 401},
		{"POST", "/lists", "NAS_SID=valid", "https://evil.example", 403},
		{"POST", "/login", "", "", 302},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Cookie", tc.cookie)
		req.Header.Set("Origin", tc.origin)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("%s %s: got %d, want %d", tc.method, tc.path, resp.StatusCode, tc.status)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("untrusted credentials caused %d upstream calls", calls.Load())
	}
}

func TestQNAPProtocolAndUserFailures(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"expired", "<QDocRoot><authPassed>0</authPassed></QDocRoot>", 200, errQNAPSession},
		{"error", "<QDocRoot><authPassed>1</authPassed><errorValue>-4</errorValue></QDocRoot>", 200, errQNAPSession},
		{"forbidden user", "<QDocRoot><authPassed>1</authPassed><username>bob</username></QDocRoot>", 200, errQNAPUser},
		{"missing fields", "<QDocRoot/>", 200, nil},
		{"missing identity", "<QDocRoot><authPassed>1</authPassed></QDocRoot>", 200, nil},
		{"wrong root", "<html><authPassed>1</authPassed></html>", 200, nil},
		{"malformed", "<QDocRoot>", 200, nil},
		{"oversized", strings.Repeat("x", (1<<20)+1), 200, nil},
		{"http error", "", 503, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			auth.allowedUsers = map[string]bool{"alice": true}
			_, err := auth.validate("sid")
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.want == nil && (errors.Is(err, errQNAPSession) || errors.Is(err, errQNAPUser)) {
				t.Fatalf("service failure incorrectly treated as a login failure: %v", err)
			}
		})
	}
}

func TestQNAPDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(true)
	}))
	defer target.Close()
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	if _, err := auth.validate("sid"); err == nil || leaked.Load() {
		t.Fatal("authentication redirect was followed or accepted")
	}
}

func TestQNAPStatusAndUnavailableNAS(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	})
	qnapUseTestAuth(t, auth)
	app := fiber.New()
	app.Get("/auth/qts/status", QNAPAuthStatus)
	app.Use(AuthMiddleware)
	app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(200) })
	for _, path := range []string{"/auth/qts/status", "/"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Cookie", "NAS_SID=valid-looking")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 503 {
			t.Errorf("%s: expected 503, got %d", path, resp.StatusCode)
		}
	}
}

func TestQNAPAPIOriginConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, api, fallback, want string
		invalid                   bool
	}{
		{name: "API alone", api: "https://nas.example:9443", want: "https://nas.example:9443/cgi-bin/authLogin.cgi"},
		{name: "legacy fallback", fallback: "https://legacy.example", want: "https://legacy.example/cgi-bin/authLogin.cgi"},
		{name: "API takes precedence", api: "https://api.example", fallback: "https://legacy.example", want: "https://api.example/cgi-bin/authLogin.cgi"},
		{name: "invalid browser origin", api: "https://api.example", fallback: "invalid", invalid: true},
		{name: "missing origin", invalid: true},
		{name: "invalid API cannot fall back", api: "invalid", fallback: "https://legacy.example", invalid: true},
		{name: "invalid legacy origin", fallback: "invalid", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("QNAP_AUTH", "true")
			t.Setenv("DISABLE_AUTH", "false")
			t.Setenv("QNAP_CA_CERT", "")
			t.Setenv("QNAP_ALLOWED_USERS", "")
			t.Setenv("QNAP_API_URL", tc.api)
			t.Setenv("QNAP_URL", tc.fallback)
			auth, err := qnapAuthFromEnv()
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid configuration accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			expectedLogin := tc.fallback
			if expectedLogin == "" {
				expectedLogin = tc.api
			}
			if auth.loginURL != expectedLogin+"/cgi-bin/login.html" {
				t.Fatalf("unexpected browser URL: %s", auth.loginURL)
			}
			if auth.apiURL != tc.want {
				t.Fatalf("API URL = %q, want %q", auth.apiURL, tc.want)
			}
		})
	}
}

func TestQNAPConfigurationAndReturnPaths(t *testing.T) {
	qnapTestAuth(t, func(http.ResponseWriter, *http.Request) {})
	for _, name := range []string{"DISABLE_AUTH"} {
		t.Setenv(name, "true")
		if _, err := qnapAuthFromEnv(); err == nil {
			t.Errorf("conflicting %s was accepted", name)
		}
		t.Setenv(name, "false")
	}
	t.Setenv("MULTI_USER", "true")
	if _, err := qnapAuthFromEnv(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QNAP_AUTH", "TRUE")
	if _, err := qnapAuthFromEnv(); err == nil {
		t.Error("invalid mode was accepted")
	}
	t.Setenv("QNAP_AUTH", "false")
	if auth, err := qnapAuthFromEnv(); err != nil || auth != nil {
		t.Error("disabled mode changed legacy authentication")
	}
	for _, raw := range []string{"", "/relative", "file:///etc/passwd", "https://u:p@nas", "https://nas/path", "https://nas/?sid=x", "https://nas/#x"} {
		if _, err := qnapOrigin(raw); err == nil {
			t.Errorf("invalid QTS origin accepted: %q", raw)
		}
	}
	for _, raw := range []string{"https://evil.example", "//evil.example", "/%2f/evil.example", "/%5cevil.example", "/%0d%0a", "/login", "/logout", "/auth/qts/status"} {
		if got := qnapReturnPath(raw); got != "/" {
			t.Errorf("unsafe return path %q accepted as %q", raw, got)
		}
	}
	if got := qnapReturnPath("/lists/42?view=all"); got != "/lists/42?view=all" {
		t.Fatalf("lost original destination: %q", got)
	}
}
