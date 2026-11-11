package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"shopping-list/db"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v2"
)

type qnapAccount struct {
	user      *db.User
	workspace int64
	cookie    string
	sid       string
}

func qnapAccountApp(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New()
	app.Post("/logout", Logout)
	app.Use(AuthMiddleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"user": CurrentUser(c), "workspace": WorkspaceID(c)})
	})
	RegisterRoutes(app)
	return app
}

func qnapAccountRequest(t *testing.T, app *fiber.App, sid, cookie, method, path string, form url.Values, headers map[string]string) authResult {
	t.Helper()
	h := map[string]string{"Cookie": "NAS_SID=" + sid + "; session=" + cookie}
	for k, v := range headers {
		h[k] = v
	}
	return authDo(t, app, "", method, path, form, h)
}

func qnapSignIn(t *testing.T, app *fiber.App, sid string) qnapAccount {
	t.Helper()
	first := qnapAccountRequest(t, app, sid, "", "GET", "/", nil, nil)
	if first.status != 200 || !strings.Contains(first.body, "indexedDB.deleteDatabase") {
		t.Fatalf("missing account cache reset: %d %s", first.status, first.body)
	}
	resp := &http.Response{Header: first.header}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected a bound session cookie, got %v", cookies)
	}
	cookie := cookies[0].Value
	page := qnapAccountRequest(t, app, sid, cookie, "GET", "/", nil, nil)
	var data struct {
		User      db.User
		Workspace int64
	}
	if page.status != 200 || json.Unmarshal([]byte(page.body), &data) != nil {
		t.Fatalf("signed-in page: %d %s", page.status, page.body)
	}
	return qnapAccount{&data.User, data.Workspace, cookie, sid}
}

func TestQNAPAccountsAreIsolatedAndCanShareExplicitly(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("sid")
		admin := 0
		if name == "admin" {
			admin = 1
		}
		fmt.Fprintf(w, "<QDocRoot><authPassed>1</authPassed><username>%s</username><isAdmin>%d</isAdmin></QDocRoot>", name, admin)
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapAccountApp(t)
	legacy, err := db.CreateList(db.DefaultWorkspaceID, "Old shared list", "")
	if err != nil {
		t.Fatal(err)
	}
	// Signing in first does not give a non-admin the old shared data.
	alice := qnapSignIn(t, app, "alice")
	bob := qnapSignIn(t, app, "bob")
	admin := qnapSignIn(t, app, "admin")
	if alice.user.IsAdmin || bob.user.IsAdmin || !admin.user.IsAdmin {
		t.Fatal("Koffan roles do not match verified QTS roles")
	}
	if alice.workspace == bob.workspace || alice.workspace == db.DefaultWorkspaceID || bob.workspace == db.DefaultWorkspaceID {
		t.Fatal("QTS users share a workspace by default")
	}
	if admin.workspace != db.DefaultWorkspaceID || db.MemberRole(db.DefaultWorkspaceID, admin.user.ID) != db.RoleOwner {
		t.Fatal("QTS administrator did not inherit existing shopping data")
	}
	list, err := db.CreateList(alice.workspace, "Alice private list", "")
	if err != nil {
		t.Fatal(err)
	}
	section, err := db.CreateSectionForList(list.ID, "Alice private section")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, method string }{
		{"/api/data?list_id=" + strconv.FormatInt(list.ID, 10), "GET"},
		{"/lists/" + strconv.FormatInt(list.ID, 10), "PUT"},
		{"/sections/" + strconv.FormatInt(section.ID, 10) + "/items", "GET"},
		{"/api/data?list_id=" + strconv.FormatInt(legacy.ID, 10), "GET"},
	} {
		resp := qnapAccountRequest(t, app, bob.sid, bob.cookie, tc.method, tc.path, nil, nil)
		if resp.status != 404 {
			t.Errorf("cross-account %s %s returned %d: %s", tc.method, tc.path, resp.status, resp.body)
		}
	}
	snapshot := qnapAccountRequest(t, app, bob.sid, bob.cookie, "GET", "/api/offline/snapshot", nil, nil)
	if snapshot.status != 200 || strings.Contains(snapshot.body, "Alice private") || strings.Contains(snapshot.body, "Old shared list") {
		t.Fatalf("private data in Bob's offline snapshot: %d %s", snapshot.status, snapshot.body)
	}
	if err := db.AddMember(alice.workspace, bob.user.ID, db.RoleMember); err != nil {
		t.Fatal(err)
	}
	switched := qnapAccountRequest(t, app, bob.sid, bob.cookie, "POST", "/workspaces/"+strconv.FormatInt(alice.workspace, 10)+"/switch", nil, nil)
	if switched.status != 200 {
		t.Fatalf("workspace switch: %d %s", switched.status, switched.body)
	}
	shared := qnapAccountRequest(t, app, bob.sid, bob.cookie, "GET", "/api/offline/snapshot", nil, nil)
	if shared.status != 200 || !strings.Contains(shared.body, "Alice private list") {
		t.Fatalf("explicit sharing failed: %d %s", shared.status, shared.body)
	}
	client := &webSocketClient{qnapSID: bob.sid, sessionID: bob.cookie, userID: bob.user.ID, workspaceID: alice.workspace}
	if !socketStillAllowed(client) {
		t.Fatal("member's live feed denied")
	}
	if err := db.RemoveMember(alice.workspace, bob.user.ID); err != nil {
		t.Fatal(err)
	}
	if socketStillAllowed(client) {
		t.Fatal("removed member still receives private live updates")
	}
}

func TestQNAPAccountSwitchRejectsStaleWritesAndSessions(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<QDocRoot><authPassed>1</authPassed><username>%s</username></QDocRoot>", r.FormValue("sid"))
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapAccountApp(t)
	alice := qnapSignIn(t, app, "alice")
	stale := qnapAccountRequest(t, app, "bob", alice.cookie, "POST", "/lists", url.Values{"name": {"stale shopping"}}, nil)
	if stale.status != 409 || stale.header.Get(WorkspaceMismatchHeader) != "1" {
		t.Fatalf("stale write accepted: %d %s", stale.status, stale.body)
	}
	if n := db.CountUsers(); n != 2 {
		t.Fatalf("expected two distinct QTS identities, got %d", n)
	}
	page := qnapAccountRequest(t, app, "bob", alice.cookie, "GET", "/", nil, nil)
	if page.status != 200 || !strings.Contains(page.body, "indexedDB.deleteDatabase") {
		t.Fatal("account switch did not reset cached data")
	}
	if _, err := db.GetSession(alice.cookie); err == nil {
		t.Fatal("old browser session was not revoked")
	}
	bob := qnapSignIn(t, app, "bob")
	stale = qnapAccountRequest(t, app, "bob", bob.cookie, "POST", "/lists", url.Values{"name": {"stale shopping"}}, map[string]string{"X-Koffan-User": strconv.FormatInt(alice.user.ID, 10)})
	if stale.status != 409 {
		t.Fatalf("old account's page accepted under new cookies: %d", stale.status)
	}
	noQTS := qnapAccountRequest(t, app, "", bob.cookie, "GET", "/", nil, nil)
	if noQTS.status != 302 {
		t.Fatalf("local session bypassed QTS: %d", noQTS.status)
	}
	replay := qnapAccountRequest(t, app, "alice", bob.cookie, "GET", "/api/offline/snapshot", nil, nil)
	if replay.status != 409 {
		t.Fatalf("SID/session mismatch accepted: %d", replay.status)
	}
}

func TestQNAPRolesAndLocalAccountConflicts(t *testing.T) {
	var admin atomic.Int32
	admin.Store(1)
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<QDocRoot><authPassed>1</authPassed><username>%s</username><isAdmin>%d</isAdmin></QDocRoot>", r.FormValue("sid"), admin.Load())
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapAccountApp(t)
	user := qnapSignIn(t, app, "admin")
	for _, path := range []string{"/admin/users", "/admin/users/123/delete", "/admin/users/123/password", "/account/password"} {
		resp := qnapAccountRequest(t, app, user.sid, user.cookie, "POST", path, nil, nil)
		if resp.status != 403 {
			t.Errorf("local account management %s returned %d", path, resp.status)
		}
	}
	admin.Store(0)
	page := qnapAccountRequest(t, app, user.sid, user.cookie, "GET", "/", nil, nil)
	if page.status != 200 || strings.Contains(page.body, "\"is_admin\":true") {
		t.Fatal("QTS admin demotion was not applied")
	}
	if db.CheckPassword(user.user.ID, "shopping123") {
		t.Fatal("provisioned account has a local password")
	}
	_, err := db.CreateUser("local", "Local account", "a private password", true)
	if err != nil {
		t.Fatal(err)
	}
	conflict := qnapAccountRequest(t, app, "local", "", "GET", "/", nil, nil)
	if conflict.status != 409 {
		t.Fatalf("QTS identity took over a local account: %d %s", conflict.status, conflict.body)
	}
}

func TestQNAPWorkspacePageUsesQTSAccountControls(t *testing.T) {
	tmpl, err := template.New("workspaces").Funcs(template.FuncMap{
		"initial": func(string) string { return "A" },
		"toJSON": func(v interface{}) template.JS {
			data, _ := json.Marshal(v)
			return template.JS(data)
		},
		"dict": func(values ...interface{}) map[string]interface{} {
			result := map[string]interface{}{}
			for i := 0; i < len(values); i += 2 {
				result[values[i].(string)] = values[i+1]
			}
			return result
		},
	}).ParseFiles("../templates/workspaces.html")
	if err != nil {
		t.Fatal(err)
	}
	admin := db.User{ID: 1, Username: "admin", DisplayName: "Admin", IsAdmin: true}
	bob := db.User{ID: 2, Username: "bob", DisplayName: "Bob"}
	var output bytes.Buffer
	if err := tmpl.ExecuteTemplate(&output, "workspaces", fiber.Map{
		"User": admin, "QNAPAuth": true, "AllUsers": []db.User{admin, bob}, "Icons": WorkspaceIcons,
	}); err != nil {
		t.Fatal(err)
	}
	page := output.String()
	for _, forbidden := range []string{"action=\"/account/password\"", "action=\"/admin/users", "name=\"password\""} {
		if strings.Contains(page, forbidden) {
			t.Errorf("local account control present in QTS mode: %s", forbidden)
		}
	}
	if !strings.Contains(page, "@admin") || !strings.Contains(page, "@bob") || !strings.Contains(page, "qts.account_managed") {
		t.Fatal("QTS users or account-management notice missing")
	}
}

func TestQNAPSessionsCannotBecomeLocalPasswordSessions(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapAccountApp(t)
	alice := qnapSignIn(t, app, "alice")
	qnapAuth = nil
	t.Setenv("MULTI_USER", "true")
	page := authDo(t, app, alice.cookie, "GET", "/", nil, nil)
	if page.status != 302 || page.location != "/login" {
		t.Fatalf("QTS-only session accepted after disabling QTS: %d %s", page.status, page.body)
	}
}

func TestQNAPAdoptsApprovedLegacyAccountsWithoutChangingTheirData(t *testing.T) {
	for _, name := range []string{"admin", "marti.mas", "nurieta"} {
		t.Run(name, func(t *testing.T) {
			auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
				admin := 0
				if name == "admin" {
					admin = 1
				}
				fmt.Fprintf(w, "<QDocRoot><authPassed>1</authPassed><username>%s</username><isAdmin>%d</isAdmin></QDocRoot>", name, admin)
			})
			qnapUseTestAuth(t, auth)
			initTestDatabase(t)
			legacy := newGuardHousehold(t, name)
			// Local admin status must not override the current QTS role.
			if _, err := db.DB.Exec("UPDATE users SET display_name = ?, is_admin = TRUE WHERE id = ?", "Existing display name", legacy.user.ID); err != nil {
				t.Fatal(err)
			}
			oldSession := sessionFor(t, legacy.user, legacy.workspace.ID)
			app := qnapAccountApp(t)
			account := qnapSignIn(t, app, name)
			if account.user.ID != legacy.user.ID || account.workspace != legacy.workspace.ID || account.user.DisplayName != "Existing display name" {
				t.Fatalf("legacy account was replaced rather than adopted: %+v", account)
			}
			if account.user.IsAdmin != (name == "admin") {
				t.Fatal("adopted account's privileges do not match QTS")
			}
			if _, err := db.GetSession(oldSession); err == nil {
				t.Fatal("old local-password session survived migration")
			}
			if db.CheckPassword(legacy.user.ID, "correct horse battery") {
				t.Fatal("old local password survived migration")
			}
			snapshot := qnapAccountRequest(t, app, account.sid, account.cookie, "GET", "/api/offline/snapshot", nil, nil)
			if snapshot.status != 200 || !strings.Contains(snapshot.body, name+" list") || !strings.Contains(snapshot.body, name+" milk") {
				t.Fatalf("legacy shopping data was lost: %d %s", snapshot.status, snapshot.body)
			}
			again := qnapSignIn(t, app, name)
			workspaces, err := db.WorkspacesForUser(account.user.ID)
			if err != nil || len(workspaces) != 1 || again.user.ID != account.user.ID || db.CountUsers() != 1 {
				t.Fatal("repeated QTS login duplicated the account or workspace")
			}
		})
	}
}

func TestQNAPLegacyAdoptionRequiresExactApprovedName(t *testing.T) {
	qnapUseTestAuth(t, qnapTestAuth(t, func(http.ResponseWriter, *http.Request) {}))
	initTestDatabase(t)
	legacy := newGuardHousehold(t, "ADMIN")
	if _, err := db.EnsureQNAPUser("admin", true); err != db.ErrQNAPIdentityConflict {
		t.Fatalf("case-different local account was adopted: %v", err)
	}
	if !db.CheckPassword(legacy.user.ID, "correct horse battery") {
		t.Fatal("failed adoption changed the existing account")
	}
	if _, err := db.QNAPUserID("admin"); err == nil {
		t.Fatal("failed adoption left a linked identity")
	}
}

func TestQNAPInvalidSessionCannotAdoptLegacyAccount(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<QDocRoot><authPassed>0</authPassed><username>admin</username><isAdmin>1</isAdmin></QDocRoot>")
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	legacy := newGuardHousehold(t, "admin")
	app := qnapAccountApp(t)
	page := qnapAccountRequest(t, app, "expired-or-forged", "", "GET", "/", nil, map[string]string{"Cookie": "NAS_SID=expired-or-forged; NAS_USER=admin"})
	if page.status != 302 {
		t.Fatalf("invalid QTS session accepted: %d", page.status)
	}
	if _, err := db.QNAPUserID("admin"); err == nil {
		t.Fatal("invalid QTS session adopted the local account")
	}
	if !db.CheckPassword(legacy.user.ID, "correct horse battery") {
		t.Fatal("unauthenticated request changed the local account")
	}
}

func TestQNAPRenewedSIDPreservesVerifiedUsersWorkspaceAndOfflineOwner(t *testing.T) {
	auth := qnapTestAuth(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<QDocRoot><authPassed>1</authPassed><username>alice</username></QDocRoot>")
	})
	qnapUseTestAuth(t, auth)
	initTestDatabase(t)
	app := qnapAccountApp(t)
	account := qnapSignIn(t, app, "old-sid")
	workspace, err := db.CreateWorkspace("Another workspace", "", account.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetSessionWorkspace(account.cookie, workspace.ID); err != nil {
		t.Fatal(err)
	}
	response := qnapAccountRequest(t, app, "renewed-sid", account.cookie, "GET", "/", nil, nil)
	if response.status != 200 {
		t.Fatal(response.status)
	}
	var sessionID string
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Name == SessionCookieName {
			sessionID = cookie.Value
		}
	}
	session, err := db.GetSession(sessionID)
	if err != nil || session.WorkspaceID != workspace.ID {
		t.Fatalf("selected workspace lost: %+v %v", session, err)
	}
	owner := fmt.Sprintf("%d:%d", account.user.ID, workspace.ID)
	if !strings.Contains(response.body, `var owner = "`+owner+`"`) {
		t.Fatal("session renewal did not condition cleanup on the verified offline owner")
	}
}
