package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

const localQNAPSID = "qnap_sid"

var (
	qnapAuth *qnapAuthenticator
	errQNAPSession = errors.New("QTS session missing or expired")
	errQNAPUser = errors.New("QTS user is not allowed to use Koffan")
)

// Configuration is immutable after startup. Never infer the API destination
// from an incoming Host header or forward browser-supplied URLs to the NAS.
type qnapAuthenticator struct {
	apiURL string
	loginURL string
	client *http.Client
	allowedUsers map[string]bool
}

// InitQNAPAuth must run before registering handlers or initializing accounts.
func InitQNAPAuth() error {
	auth, err := qnapAuthFromEnv()
	if err != nil {
		return err
	}
	qnapAuth = auth
	return nil
}

func qnapOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, errors.New("must be an HTTP(S) origin without credentials, path or query")
	}
	u.Path = ""
	return u, nil
}

func qnapAuthFromEnv() (*qnapAuthenticator, error) {
	mode := os.Getenv("QNAP_AUTH")
	if mode == "" || mode == "false" {
		return nil, nil
	}
	if mode != "true" {
		return nil, errors.New("QNAP_AUTH must be exactly true or false")
	}
	if os.Getenv("DISABLE_AUTH") == "true" || os.Getenv("MULTI_USER") == "true" {
		return nil, errors.New("QNAP_AUTH=true requires DISABLE_AUTH and MULTI_USER to be unset or false")
	}
	public, err := qnapOrigin(os.Getenv("QNAP_URL"))
	if err != nil {
		return nil, fmt.Errorf("QNAP_URL: %w", err)
	}
	internal := os.Getenv("QNAP_API_URL")
	if internal == "" {
		internal = public.String()
	}
	api, err := qnapOrigin(internal)
	if err != nil {
		return nil, fmt.Errorf("QNAP_API_URL: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if certPath := os.Getenv("QNAP_CA_CERT"); certPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA certificates: %w", err)
		}
		pem, err := os.ReadFile(certPath)
		if err != nil {
			return nil, errors.New("cannot read QNAP_CA_CERT")
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("QNAP_CA_CERT contains no PEM certificates")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	users := make(map[string]bool)
	if raw := os.Getenv("QNAP_ALLOWED_USERS"); raw != "" {
		for _, name := range strings.Split(raw, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				return nil, errors.New("QNAP_ALLOWED_USERS contains an empty username")
			}
			users[name] = true
		}
	}
	api.Path = "/cgi-bin/authLogin.cgi"
	public.Path = "/cgi-bin/login.html"
	return &qnapAuthenticator{
		apiURL: api.String(), loginURL: public.String(), allowedUsers: users,
		client: &http.Client{
			Transport: transport, Timeout: 5 * time.Second,
			// Never follow redirects carrying authentication material.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// validate uses QTS's documented Login with sid API. NAS_USER is not trusted
// as identity. Query-string SIDs and Koffan session cookies are not accepted.
func (a *qnapAuthenticator) validate(sid string) (string, error) {
	if sid == "" || len(sid) > 256 || strings.ContainsAny(sid, "\r\n") {
		return "", errQNAPSession
	}
	// POST keeps the SID out of URLs and proxy access logs.
	resp, err := a.client.PostForm(a.apiURL, url.Values{"sid": {sid}})
	if err != nil {
		return "", errors.New("QTS authentication service is unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("QTS authentication service returned an unexpected HTTP status")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return "", errors.New("invalid QTS authentication response")
	}
	var result struct {
		XMLName xml.Name `xml:"QDocRoot"`
		AuthPassed *int `xml:"authPassed"`
		ErrorValue int `xml:"errorValue"`
		Username string `xml:"username"`
	}
	if err := xml.Unmarshal(body, &result); err != nil || result.AuthPassed == nil {
		return "", errors.New("invalid QTS authentication response")
	}
	if *result.AuthPassed != 1 || result.ErrorValue != 0 {
		return "", errQNAPSession
	}
	if result.Username == "" {
		return "", errors.New("QTS authentication response has no username")
	}
	if len(a.allowedUsers) > 0 && !a.allowedUsers[result.Username] {
		return "", errQNAPUser
	}
	return result.Username, nil
}

// Keep return destinations local, including encoded navigation separators.
func qnapReturnPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" ||
		!strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") ||
		strings.ContainsAny(u.Path, "\\\r\n") || u.Fragment != "" ||
		u.Path == "/login" || u.Path == "/logout" || strings.HasPrefix(u.Path, "/auth/") {
		return "/"
	}
	return u.String()
}

func qnapFailure(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, errQNAPUser):
		return c.Status(fiber.StatusForbidden).SendString("This QTS account is not allowed to use Koffan.")
	case errors.Is(err, errQNAPSession):
		next := "/login?next=" + url.QueryEscape(qnapReturnPath(c.OriginalURL()))
		if c.Get("HX-Request") == "true" {
			c.Set("HX-Redirect", next)
			return c.SendStatus(fiber.StatusUnauthorized)
		}
		if c.Path() == "/ws" || strings.HasPrefix(c.Path(), "/api/") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "qts_login_required", "login_url": next})
		}
		return c.Redirect(next)
	default:
		return c.Status(fiber.StatusServiceUnavailable).SendString("QTS authentication is unavailable. Try again shortly.")
	}
}

func qnapAuthMiddleware(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	if crossOriginRequest(c) {
		return c.SendStatus(fiber.StatusForbidden)
	}
	// The SID can outlive Fiber's pooled request buffer in a WebSocket.
	sid := strings.Clone(c.Cookies("NAS_SID"))
	user, err := qnapAuth.validate(sid)
	if err != nil {
		return qnapFailure(c, err)
	}
	c.Locals(localQNAPSID, sid)
	c.Locals("qnap_user", user)
	return c.Next()
}

func qnapLoginPage(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	c.Set("Referrer-Policy", "no-referrer")
	next := qnapReturnPath(c.Query("next", "/"))
	if _, err := qnapAuth.validate(c.Cookies("NAS_SID")); err == nil {
		return c.Redirect(next)
	} else if !errors.Is(err, errQNAPSession) {
		return qnapFailure(c, err)
	}
	return c.Render("qnap-login", fiber.Map{
		"QTSLoginURL": qnapAuth.loginURL, "Next": next,
	}, "")
}

// This probe sits outside the middleware so it never redirects while waiting.
func QNAPAuthStatus(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	if qnapAuth == nil {
		return c.SendStatus(fiber.StatusNotFound)
	}
	_, err := qnapAuth.validate(c.Cookies("NAS_SID"))
	status := fiber.StatusOK
	if errors.Is(err, errQNAPSession) {
		status = fiber.StatusUnauthorized
	} else if errors.Is(err, errQNAPUser) {
		status = fiber.StatusForbidden
	} else if err != nil {
		status = fiber.StatusServiceUnavailable
	}
	return c.Status(status).JSON(fiber.Map{"authenticated": err == nil})
}

func qnapLogout(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	if crossOriginRequest(c) {
		return c.SendStatus(fiber.StatusForbidden)
	}
	// Do not silently destroy the NAS session used by other applications.
	return c.Render("qnap-logout", fiber.Map{"QTSLoginURL": qnapAuth.loginURL}, "")
}

// HTTP writes validate immediately. Long-lived feeds are revoked within
// 30 seconds plus the API timeout, including when the NAS is unreachable.
func watchQNAPSocket(client *webSocketClient) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-client.done:
			return
		case <-ticker.C:
			if !socketStillAllowed(client) {
				_ = client.close()
				return
			}
		}
	}
}
