package handlers

import (
	"encoding/xml"
	"errors"
	"io"
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
	if logoutErr == nil {
		// The normal QTS cookies are host scoped. Clear remembered-login data as
		// well so the sign-in page does not immediately reuse it in this browser.
		for _, name := range []string{"NAS_SID", "NAS_USER", "qtoken"} {
			for _, path := range []string{"/", "/cgi-bin"} {
				c.Cookie(&fiber.Cookie{Name: name, Value: "", Path: path,
					Expires: time.Unix(1, 0), MaxAge: -1, HTTPOnly: true,
					Secure: isSecureConnection(c), SameSite: "Lax"})
			}
		}
	}
	// On failure retain the NAS cookie for an explicit retry. Never silently
	// redirect to /login, which could immediately authenticate the user again.
	if logoutErr != nil {
		c.Status(fiber.StatusBadGateway)
	} else if localErr != nil {
		c.Status(fiber.StatusServiceUnavailable)
	}
	return c.Render("qnap-logout", fiber.Map{
		"QTSLogoutFailed": logoutErr != nil, "LocalLogoutFailed": localErr != nil,
	}, "")
}
