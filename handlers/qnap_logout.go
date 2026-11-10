package handlers

import (
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"shopping-list/db"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// QTS reports a completed logout with authPassed=0, unlike a successful login.
// Confirm the SID is invalid afterward; a 200 response alone is not sufficient.
func (a *qnapAuthenticator) logout(sid string) error {
	if sid == "" {
		return nil
	}
	if len(sid) > 256 || strings.ContainsAny(sid, "\r\n") {
		return errors.New("invalid QTS session")
	}
	endpoint, err := url.Parse(a.apiURL)
	if err != nil {
		return errors.New("invalid QTS logout endpoint")
	}
	endpoint.Path = "/cgi-bin/authLogout.cgi"
	resp, err := a.client.PostForm(endpoint.String(), url.Values{"sid": {sid}, "logout": {"1"}})
	if err != nil {
		return errors.New("QTS logout service is unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("QTS logout returned an unexpected HTTP status")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return errors.New("invalid QTS logout response")
	}
	var result struct {
		XMLName    xml.Name `xml:"QDocRoot"`
		AuthPassed *int     `xml:"authPassed"`
		ErrorValue int      `xml:"errorValue"`
	}
	if xml.Unmarshal(body, &result) != nil || result.AuthPassed == nil ||
		*result.AuthPassed != 0 || result.ErrorValue != 0 {
		return errors.New("QTS did not confirm logout")
	}
	if _, err := a.authenticate(sid); !errors.Is(err, errQNAPSession) {
		return errors.New("could not confirm that the QTS session was revoked")
	}
	return nil
}

func qnapLogout(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	c.Set("Referrer-Policy", "no-referrer")
	if crossOriginRequest(c) {
		return c.SendStatus(fiber.StatusForbidden)
	}
	sid := strings.Clone(c.Cookies("NAS_SID"))
	id := strings.Clone(c.Cookies(SessionCookieName))
	// Remove every local workspace session using this NAS SID, including other
	// tabs. Other independently authenticated NAS sessions are not affected.
	var localErr error
	if sid != "" {
		localErr = db.DeleteQNAPSessions(qnapSIDHash(sid))
	}
	if id != "" {
		if err := db.DeleteSession(id); err != nil {
			localErr = err
		}
	}
	closeWebSockets(func(client *webSocketClient) bool {
		return (sid != "" && client.qnapSID == sid) || (id != "" && client.sessionID == id)
	})
	clearSessionCookie(c)
	logoutErr := qnapAuth.logout(sid)
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
	for _, name := range []string{SessionCookieName, "NAS_SID", "NAS_USER", "qtoken", "koffan_qts_sid", "koffan_qts_login_nonce"} {
		for _, domain := range domains {
			for _, path := range []string{"/", "/cgi-bin"} {
				cookie := &http.Cookie{Name: name, Value: "", Path: path, Domain: domain,
					Expires: time.Unix(1, 0), MaxAge: -1, HttpOnly: true,
					Secure: isSecureConnection(c), SameSite: http.SameSiteLaxMode}
				// Fiber Cookie replaces earlier cookies with the same name,
				// dropping other paths/domains. Append each Set-Cookie separately.
				c.Response().Header.Add("Set-Cookie", cookie.String())
			}
		}
	}
	// A NAS outage must not keep this browser signed in. Never include session
	// values in logs or retain credentials in order to offer a retry page.
	if logoutErr != nil {
		log.Printf("QTS logout: remote session revocation could not be confirmed: %v", logoutErr)
	}
	if localErr != nil {
		log.Print("QTS logout: could not remove all local workspace sessions")
	}
	// A blank document clears offline storage before returning to the app root.
	return c.Render("qnap-logout", fiber.Map{}, "")
}
