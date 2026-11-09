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
	app.Use(AuthMiddleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"user": CurrentUser(c), "workspace": WorkspaceID(c)})
	})
	return app
}

func TestQNAPLogoutRevokesNASAndAllMatchingLocalSessions(t *testing.T) {
	var revoked atomic.Bool
	var logoutCalls atomic.Int32
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		sid := r.FormValue("sid")
		if r.URL.Path == "/cgi-bin/authLogout.cgi" {
			logoutCalls.Add(1)
			if r.Method != "POST" || r.URL.RawQuery != "" || r.FormValue("logout") != "1" || sid != "alice" || r.Header.Get("Cookie") != "" {
				t.Error("logout must send only this SID and logout=1 in the POST body")
			}
			revoked.Store(true)
			fmt.Fprint(w, "<QDocRoot><authPassed><![CDATA[0]]></authPassed></QDocRoot>")
			return
		}
		if sid == "alice" && revoked.Load() {
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	useFakeSockets(t)
	app := qnapLogoutTestApp(t)
	first := qnapSignIn(t, app, "alice")
	second := qnapSignIn(t, app, "alice")
	other := qnapSignIn(t, app, "alice-other-device")
	socket := connectFakeSocket(first.workspace, first.user.ID, first.cookie, time.Now().Add(time.Hour).Unix())
	socket.client.qnapSID = first.sid
	otherSocket := connectFakeSocket(other.workspace, other.user.ID, other.cookie, time.Now().Add(time.Hour).Unix())
	otherSocket.client.qnapSID = other.sid
	response := qnapAccountRequest(t, app, first.sid, first.cookie, "POST", "/logout", nil, nil)
	if response.status != 200 || !strings.Contains(response.body, "You are signed out") || response.location != "" {
		t.Fatalf("logout did not stay on a signed-out page: %d %s", response.status, response.body)
	}
	if logoutCalls.Load() != 1 || !revoked.Load() {
		t.Fatal("QTS logout was not invoked")
	}
	for _, cookie := range []string{first.cookie, second.cookie} {
		if _, err := db.GetSession(cookie); err == nil {
			t.Fatal("matching local session survived logout")
		}
	}
	if _, err := db.GetSession(other.cookie); err != nil {
		t.Fatal("another independent NAS session was signed out")
	}
	if !socket.closed() || otherSocket.closed() {
		t.Fatal("wrong live feeds were closed")
	}
	expired := map[string]bool{}
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Expires.Before(time.Now()) {
			expired[cookie.Name] = true
		}
	}
	for _, name := range []string{SessionCookieName, "NAS_SID", "NAS_USER", "qtoken"} {
		if !expired[name] {
			t.Errorf("%s cookie was not cleared", name)
		}
	}
	replay := qnapAccountRequest(t, app, first.sid, first.cookie, "GET", "/", nil, nil)
	if replay.status != 302 {
		t.Fatalf("revoked NAS session still opens Koffan: %d", replay.status)
	}
}

func TestQNAPLogoutFailureIsVisibleAndRetryable(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var revoked atomic.Bool
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/authLogout.cgi" {
			if fail.Load() {
				w.WriteHeader(503)
				return
			}
			revoked.Store(true)
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else if revoked.Load() {
			fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
		} else {
			fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
		}
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapLogoutTestApp(t)
	account := qnapSignIn(t, app, "alice")
	response := qnapAccountRequest(t, app, account.sid, account.cookie, "POST", "/logout", nil, nil)
	if response.status != 502 || !strings.Contains(response.body, "Retry sign out") || strings.Contains(response.body, "You are signed out") || response.location != "" {
		t.Fatalf("logout failure was hidden: %d %s", response.status, response.body)
	}
	if _, err := db.GetSession(account.cookie); err == nil {
		t.Fatal("local session was not revoked after NAS failure")
	}
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Name == "NAS_SID" || cookie.Name == "qtoken" {
			t.Fatal("NAS credentials were discarded before an explicit retry")
		}
	}
	fail.Store(false)
	retry := qnapAccountRequest(t, app, account.sid, "", "POST", "/logout", nil, nil)
	if retry.status != 200 || !strings.Contains(retry.body, "You are signed out") {
		t.Fatalf("retry failed: %d %s", retry.status, retry.body)
	}
}

func TestQNAPLogoutRejectsCrossOriginRequests(t *testing.T) {
	var calls atomic.Int32
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed></QDocRoot>")
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	account, err := db.EnsureQNAPUser("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	session := sessionFor(t, account, 0)
	response := qnapAccountRequest(t, qnapLogoutTestApp(t), "secret", session, "POST", "/logout", nil, map[string]string{"Origin": "https://evil.example"})
	if response.status != 403 || calls.Load() != 0 || response.header.Get("Set-Cookie") != "" {
		t.Fatal("cross-origin logout caused side effects")
	}
	if _, err := db.GetSession(session); err != nil {
		t.Fatal("cross-origin logout removed the local session")
	}
}

func TestQNAPLogoutDoesNotTrustSuccessWithoutRevocation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"still authenticated", "<QDocRoot><authPassed>0</authPassed></QDocRoot>", 200},
		{"wrong flag", "<QDocRoot><authPassed>1</authPassed></QDocRoot>", 200},
		{"missing flag", "<QDocRoot/>", 200},
		{"wrong root", "<html><authPassed>0</authPassed></html>", 200},
		{"NAS error", "<QDocRoot><authPassed>0</authPassed><errorValue>-1</errorValue></QDocRoot>", 200},
		{"HTTP failure", "", 503},
		{"redirect", "", 307},
		{"oversized", strings.Repeat("x", (1<<20)+1), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/cgi-bin/authLogout.cgi" {
					w.Header().Set("Location", "/unexpected-redirect")
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.body)
				} else if r.URL.Path == "/cgi-bin/authLogin.cgi" {
					fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
				} else {
					t.Error("logout followed a redirect")
				}
			})
			if err := auth.logout("secret-sid"); err == nil || strings.Contains(err.Error(), "secret-sid") {
				t.Fatalf("logout accepted unconfirmed revocation or leaked SID: %v", err)
			}
		})
	}
}

func TestQNAPLogoutWithoutASIDIsIdempotent(t *testing.T) {
	auth := qnapTestAuth(t, func(http.ResponseWriter, *http.Request) { t.Error("missing SID was sent to QTS") })
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	for i := 0; i < 2; i++ {
		result := qnapAccountRequest(t, qnapLogoutTestApp(t), "", "", "POST", "/logout", nil, nil)
		if result.status != 200 || !strings.Contains(result.body, "You are signed out") {
			t.Fatalf("repeated logout failed: %d %s", result.status, result.body)
		}
	}
}
