package app

import "net/http"

func handleAdminBrowser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	b := currentBrowser()
	if !cfg.BrowserEnabled || b == nil {
		writeJSON(w, 200, browserInfo{})
		return
	}
	writeJSON(w, 200, b.Status())
}

func handleAdminBrowserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	b := currentBrowser()
	if !cfg.BrowserEnabled || b == nil {
		writeJSON(w, 409, map[string]string{"error": "browser mode is disabled"})
		return
	}
	b.Login()
	writeJSON(w, 202, b.Status())
}
