package handlers

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"shopping-list/db"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

const (
	qnapAPICookie        = "koffan_qts_sid"
	qnapLoginNonceCookie = "koffan_qts_login_nonce"
	qnapLoggedOutSID     = "koffan-signed-out"
)

var (
	errQNAPCredentials     = errors.New("incorrect QTS credentials")
	errQNAPCodeNeeded      = errors.New("QTS requires a security code")
	errQNAPCredentialHTTPS = errors.New("QTS password login requires HTTPS")
	errQNAPLoginService    = errors.New("QTS sign-in service is unavailable")
)

// API-created sessions are private to Koffan. A host-scoped QTS desktop cookie
// is reused only when no explicit Koffan API session has been selected.
func qnapRequestSID(c *fiber.Ctx) string {
	if sid := c.Cookies(qnapAPICookie); sid != "" {
		if sid == qnapLoggedOutSID {
			return ""
		}
		return strings.Clone(sid)
	}
	return strings.Clone(c.Cookies("NAS_SID"))
}

func qnapLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// Passwords are sent only to the pinned NAS endpoint, in a POST body. Base64 is
// the QTS wire format, not encryption; HTTPS is mandatory outside loopback.
func (a *qnapAuthenticator) passwordSession(username, password, code string) (string, error) {
	endpoint, err := url.Parse(a.apiURL)
	if err != nil || (endpoint.Scheme != "https" && !qnapLoopback(endpoint.Hostname())) {
		return "", errQNAPCredentialHTTPS
	}
	form := url.Values{
		"user": {username}, "pwd": {base64.StdEncoding.EncodeToString([]byte(password))},
		"remme": {"0"}, "force_to_check_2sv": {"1"}, "serviceKey": {"1"},
		"client_app": {"Koffan"},
	}
	if code != "" {
		form.Set("security_code", code)
	}
	resp, err := a.client.PostForm(a.apiURL, form)
	if err != nil {
		return "", errQNAPLoginService
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errQNAPLoginService
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return "", errQNAPLoginService
	}
	var result struct {
		XMLName    xml.Name `xml:"QDocRoot"`
		AuthPassed *int     `xml:"authPassed"`
		AuthSID    string   `xml:"authSid"`
		Need2SV    int      `xml:"need_2sv"`
		ErrorValue int      `xml:"errorValue"`
	}
	if xml.Unmarshal(body, &result) != nil || result.AuthPassed == nil {
		return "", errQNAPLoginService
	}
	if result.Need2SV == 1 && code == "" {
		if result.AuthSID != "" {
			_ = a.logout(result.AuthSID)
		}
		return "", errQNAPCodeNeeded
	}
	if *result.AuthPassed != 1 || result.ErrorValue != 0 {
		return "", errQNAPCredentials
	}
	if result.AuthSID == "" || len(result.AuthSID) > 256 || strings.ContainsAny(result.AuthSID, "\r\n") {
		return "", errQNAPLoginService
	}
	return result.AuthSID, nil
}

func qnapLoginResult(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"authenticated": false, "error": code, "message": message})
}

// QNAPLogin handles Koffan's own sign-in form. It does not persist credentials
// or return NAS tokens to JavaScript, and never skips QTS two-step verification.
func QNAPLogin(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	c.Set("Referrer-Policy", "no-referrer")
	if qnapAuth == nil {
		return c.SendStatus(fiber.StatusNotFound)
	}
	if crossOriginRequest(c) {
		return qnapLoginResult(c, 403, "forbidden", "Sign in from the Koffan login page.")
	}
	if !isSecureConnection(c) && !qnapLoopback(c.IP()) {
		return qnapLoginResult(c, 400, "https_required", "Open Koffan over HTTPS before signing in.")
	}
	nonce, submitted := c.Cookies(qnapLoginNonceCookie), c.FormValue("csrf")
	if nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(submitted)) != 1 {
		return qnapLoginResult(c, 403, "page_expired", "Your sign-in page expired. Reload this page and try again.")
	}
	if loginLimiter != nil {
		if blocked, _ := loginLimiter.IsBlocked(c.IP()); blocked {
			return qnapLoginResult(c, 429, "rate_limited", "Too many sign-in attempts. Try again later.")
		}
	}
	username, password := strings.TrimSpace(c.FormValue("username")), c.FormValue("password")
	code := strings.TrimSpace(c.FormValue("security_code"))
	if len(c.Body()) > 16384 || username == "" || len(username) > 256 || password == "" || len(password) > 4096 {
		return qnapLoginResult(c, 400, "invalid_form", "Enter your QTS username and password.")
	}
	if code != "" {
		if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
			return qnapLoginResult(c, 400, "invalid_code", "Enter the six-digit code from your authenticator.")
		}
	}
	sid, err := qnapAuth.passwordSession(username, password, code)
	if err != nil {
		switch {
		case errors.Is(err, errQNAPCodeNeeded):
			return qnapLoginResult(c, 401, "security_code_required", "Enter the six-digit code from your authenticator to finish signing in.")
		case errors.Is(err, errQNAPCredentials):
			if loginLimiter != nil && loginLimiter.RecordAttempt(c.IP()) {
				return qnapLoginResult(c, 429, "rate_limited", "Too many sign-in attempts. Try again later.")
			}
			return qnapLoginResult(c, 401, "invalid_credentials", "The QTS username, password, or security code is incorrect.")
		case errors.Is(err, errQNAPCredentialHTTPS):
			return qnapLoginResult(c, 503, "nas_https_required", "The administrator must configure an HTTPS connection from Koffan to QTS for password sign-in.")
		default:
			return qnapLoginResult(c, 503, "qts_unavailable", "QTS sign-in is unavailable. Try again shortly.")
		}
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = qnapAuth.logout(sid)
		}
	}()
	// Confirm the actual session identity/role with QTS, not with form fields.
	identity, err := qnapAuth.authenticate(sid)
	if err != nil {
		if errors.Is(err, errQNAPUser) {
			return qnapLoginResult(c, 403, "account_denied", "This QTS account is not allowed to use Koffan.")
		}
		return qnapLoginResult(c, 503, "qts_unavailable", "QTS could not confirm your completed sign-in. Try again shortly.")
	}
	if _, err := db.EnsureQNAPUser(identity.Username, identity.IsAdmin); err != nil {
		if errors.Is(err, db.ErrQNAPIdentityConflict) {
			return qnapLoginResult(c, 409, "account_conflict", "A local account already uses this username. Ask the administrator to migrate it.")
		}
		return qnapLoginResult(c, 503, "database_unavailable", "Koffan could not open your account. Try again shortly.")
	}
	if old := strings.Clone(c.Cookies(SessionCookieName)); old != "" {
		if err := db.DeleteSession(old); err != nil {
			return qnapLoginResult(c, 503, "database_unavailable", "Koffan could not finish signing in. Try again shortly.")
		}
		closeWebSockets(func(client *webSocketClient) bool { return client.sessionID == old })
	}
	clearSessionCookie(c)
	c.Cookie(&fiber.Cookie{Name: qnapAPICookie, Value: sid, Path: "/", HTTPOnly: true,
		Secure: isSecureConnection(c), SameSite: "Lax"})
	c.Cookie(&fiber.Cookie{Name: qnapLoginNonceCookie, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), HTTPOnly: true, Secure: isSecureConnection(c), SameSite: "Strict"})
	if loginLimiter != nil {
		loginLimiter.ResetAttempts(c.IP())
	}
	accepted = true
	return c.JSON(fiber.Map{"authenticated": true, "redirect": qnapReturnPath(c.FormValue("next"))})
}
