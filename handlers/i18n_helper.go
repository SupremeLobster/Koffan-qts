package handlers

import (
	"encoding/json"
	"html/template"
	"shopping-list/i18n"

	"github.com/gofiber/fiber/v2"
)

// getLang extracts the user's language from the lang cookie
func getLang(c *fiber.Ctx) string {
	if lang := c.Cookies("lang"); lang != "" {
		return lang
	}
	return i18n.GetDefaultLang()
}

// withPageI18n adds the translation data every full page embeds.
func withPageI18n(c *fiber.Ctx, data fiber.Map) fiber.Map {
	// Only complete shopping documents explicitly opt in to the app's private
	// service-worker backup. HTTP/proxy caching remains disabled by auth.
	if _, shopping := data["OfflineSnapshot"]; shopping && c.Method() == fiber.MethodGet && c.Get("HX-Request") != "true" {
		c.Set("X-Koffan-Offline", "shopping-v1")
	}
	lang := i18n.ResolveLang(c.Cookies("lang"))
	data["Translations"] = i18n.PageTranslationsJSON(lang)
	data["PageLang"] = lang
	data["Locales"] = i18n.AvailableLocales()
	data["DefaultLang"] = i18n.GetDefaultLang()
	addWorkspaceContext(c, data)
	return data
}

// sendError sends a translated error message
func sendError(c *fiber.Ctx, status int, key string) error {
	return c.Status(status).SendString(i18n.Get(getLang(c), key))
}

// QTS pages are standalone, without the Alpine shopping layout. Include only
// their small catalog section for every locale so a saved language still works
// after logout removes the lang cookie, without a POST reload or extra fetch.
func withQTSI18n(c *fiber.Ctx, data fiber.Map) fiber.Map {
	lang := i18n.ResolveLang(c.Cookies("lang"))
	catalogs := make(map[string]map[string]string)
	for code, raw := range i18n.GetAllLocales() {
		strings := make(map[string]string)
		if section, ok := raw["qts"].(map[string]interface{}); ok {
			for key, value := range section {
				if text, ok := value.(string); ok {
					strings[key] = text
				}
			}
		}
		strings["retry_logout"] = i18n.Get(code, "offline.retry")
		strings["logout_title"] = i18n.Get(code, "nav.logout")
		catalogs[code] = strings
	}
	selected := catalogs[lang]
	if selected == nil {
		selected = map[string]string{}
	}
	encoded, _ := json.Marshal(map[string]interface{}{"lang": lang, "locales": catalogs})
	data["PageLang"] = lang
	data["QTS"] = selected
	// json.Marshal escapes HTML metacharacters before this trusted JSON is embedded.
	data["QTSJSON"] = template.JS(encoded)
	return data
}
