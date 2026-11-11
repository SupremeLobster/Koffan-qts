package handlers

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestManifestIsPublicAndRevalidatedAtAStableURL(t *testing.T) {
	saved := ManifestBytes
	savedHash := AssetHash
	AssetHash = "diagnostic-build"
	t.Cleanup(func() { AssetHash = savedHash })
	t.Cleanup(func() { ManifestBytes = saved })
	var err error
	ManifestBytes, err = os.ReadFile("../static/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Get("/static/manifest.json", ServeWebManifest)
	app.Use(func(c *fiber.Ctx) error { return c.SendStatus(401) })
	response, err := app.Test(httptest.NewRequest("GET", "/static/manifest.json", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.Header.Get("X-Koffan-Asset-Version") != "diagnostic-build" {
		t.Fatal("missing deployment identifier")
	}
	if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-cache" || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/manifest+json") {
		t.Fatalf("manifest not public/revalidated: %d %v", response.StatusCode, response.Header)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"name", "short_name"} {
		if data[key] != "Koffan Shopping List" {
			t.Errorf("wrong %s", key)
		}
	}
	for _, key := range []string{"id", "scope", "start_url"} {
		if data[key] != "/" {
			t.Errorf("unstable %s", key)
		}
	}
}
