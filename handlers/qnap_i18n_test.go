package handlers

import (
	"github.com/gofiber/fiber/v2"
	"io"
	"net/http"
	"shopping-list/i18n"
	"strings"
	"testing"
)

func TestQTSLocalizedServerErrorsAndStandaloneCatalogs(t *testing.T) {
	if err := i18n.Init(); err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Get("/denied", func(c *fiber.Ctx) error { return qnapFailure(c, errQNAPUser) })
	request, _ := http.NewRequest("GET", "http://example.com/denied", nil)
	request.Header.Set("Cookie", "lang=ca")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 403 || !strings.Contains(string(body), "Aquest compte de QTS") {
		t.Fatalf("untranslated error: %d %s", response.StatusCode, body)
	}
	app.Get("/catalog", func(c *fiber.Ctx) error {
		data := withQTSI18n(c, fiber.Map{})
		selected := data["QTS"].(map[string]string)
		if selected["login_title"] != "Inicia la sessió amb QTS" {
			t.Error("wrong standalone language")
		}
		return c.JSON(fiber.Map{"lang": data["PageLang"]})
	})
	request, _ = http.NewRequest("GET", "http://example.com/catalog", nil)
	request.Header.Set("Cookie", "lang=ca")
	response, err = app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
}
