package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type mockBrowserGateway struct {
	ready         atomic.Bool
	calls         atomic.Int64
	refreshes     atomic.Int64
	loginRequests atomic.Int64
}

func (b *mockBrowserGateway) Ready() bool { return b.ready.Load() }
func (b *mockBrowserGateway) Snapshot() (string, error) {
	if !b.Ready() {
		return "", fmt.Errorf("Google browser login required")
	}
	return fakeBrowserPage, nil
}
func (b *mockBrowserGateway) Refresh() error { b.refreshes.Add(1); return nil }
func (b *mockBrowserGateway) Login()         { b.loginRequests.Add(1) }
func (b *mockBrowserGateway) Status() browserInfo {
	return browserInfo{Enabled: true, Ready: b.Ready()}
}
func (b *mockBrowserGateway) Close() {}
func (b *mockBrowserGateway) Request(method, rawURL string, headers map[string]string, body []byte, onLine func(string)) (browserReply, error) {
	b.calls.Add(1)
	for _, k := range []string{"Cookie", "Authorization", "Origin", "Referer"} {
		if headers[k] != "" {
			return browserReply{}, fmt.Errorf("credential header reached browser adapter")
		}
	}
	raw := safetyFrame("BROWSER_PROXY_OK") + "\n"
	if onLine != nil {
		onLine(strings.TrimSuffix(raw, "\n"))
	}
	return browserReply{Status: 200, Headers: map[string]string{}, Body: []byte(raw), TTFB: 1}, nil
}

func withMockBrowser(t *testing.T) *mockBrowserGateway {
	t.Helper()
	resetSeedState(t)
	oldCfg, oldBackend := cfg, currentBrowser()
	b := &mockBrowserGateway{}
	b.ready.Store(true)
	cfg.BrowserEnabled, cfg.RequireLogin = true, true
	setBrowser(b)
	rtMu.Lock()
	oldRT := rtVal
	rtVal.RetryAttempts = 1
	rtVal.GeminiBLAuto = false
	rtMu.Unlock()
	t.Cleanup(func() { cfg = oldCfg; setBrowser(oldBackend); rtMu.Lock(); rtVal = oldRT; rtMu.Unlock() })
	return b
}

func TestBrowserModeIgnoresLegacyCredentials(t *testing.T) {
	b := withMockBrowser(t)
	if _, err := accountAdd("legacy", "SAPISID=FAKE_LEGACY_SECRET; SID=FAKE_LEGACY_SID", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := proxyCreate("legacy exit", "http://127.0.0.1:19999", 1); err != nil {
		t.Fatal(err)
	}
	a, ok := pickCookieAccount()
	if !ok || a.ID != 0 || a.Cookie != browserSessionMarker || strings.Contains(a.Cookie, "FAKE_LEGACY") {
		t.Fatalf("browser used stored Cookie: %+v", a)
	}
	res, err := streamGenerate("FAKE_PROMPT", "FAKE_PROMPT", Models["gemini-3.6-flash"], nil, nil)
	if err != nil || res.ProxyID != 0 || b.calls.Load() != 1 {
		t.Fatalf("browser route did not bypass legacy HTTP/proxies: %+v %v calls=%d", res, err, b.calls.Load())
	}
	var enabled int
	_ = getDB().QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&enabled)
	if enabled != 1 {
		t.Fatal("browser mode wrote its session to Cookie pool")
	}
	invalidateXSRF(browserSessionMarker)
	if b.refreshes.Load() != 1 {
		t.Fatal("XSRF invalidation did not refresh Chrome page")
	}
	if rotateAllAccounts() != defaultRotateInterval || b.calls.Load() != 1 {
		t.Fatal("legacy Cookie refresh ran in browser mode")
	}
	b.ready.Store(false)
	if _, err := streamGenerate("FAKE_PROMPT", "FAKE_PROMPT", Models["gemini-3.6-flash"], nil, nil); err == nil || b.calls.Load() != 1 {
		t.Fatal("unready browser fell back to legacy Cookie/HTTP")
	}
}

func TestBrowserModeAPICompatibility(t *testing.T) {
	withMockBrowser(t)
	for _, tc := range []struct {
		path, body string
		handler    http.HandlerFunc
	}{
		{"/v1/chat/completions", `{"model":"gemini-3.6-flash","messages":[{"role":"user","content":"FAKE_PROMPT"}]}`, handleChatCompletions},
		{"/v1/responses", `{"model":"gemini-3.6-flash","input":"FAKE_PROMPT"}`, handleResponses},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
		tc.handler(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "BROWSER_PROXY_OK") {
			t.Fatalf("API failed %s: %d %s", tc.path, w.Code, w.Body)
		}
		var value map[string]any
		if json.Unmarshal(w.Body.Bytes(), &value) != nil {
			t.Fatal("invalid API JSON")
		}
	}
}

func TestBrowserVisibilityEnv(t *testing.T) {
	for _, tc := range []struct {
		value string
		show  bool
	}{{"", false}, {"0", false}, {"false", false}, {"1", true}, {"true", true}} {
		t.Setenv("GEMINI_SHOW_BROWSER", tc.value)
		got, err := showBrowserEnv()
		if err != nil || got != tc.show {
			t.Fatalf("toggle %q returned %v %v", tc.value, got, err)
		}
	}
	t.Setenv("GEMINI_SHOW_BROWSER", "invalid")
	if _, err := showBrowserEnv(); err == nil {
		t.Fatal("invalid visibility toggle accepted")
	}
}

func TestBrowserProfileMustBeDedicated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "own-profile")
	if err := prepareBrowserProfile(dir); err != nil {
		t.Fatal(err)
	}
	if err := prepareBrowserProfile(dir); err != nil {
		t.Fatal("own profile cannot be reused")
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "Cookies"), []byte("FAKE_OTHER_PROFILE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareBrowserProfile(other); err == nil {
		t.Fatal("existing unrelated profile accepted")
	}
}

func TestBrowserAdminDoesNotAcceptCookieImport(t *testing.T) {
	b := withMockBrowser(t)
	w := httptest.NewRecorder()
	handleAdminCookies(w, httptest.NewRequest("POST", "/admin/api/cookies", strings.NewReader(`{"cookie":"SID=FAKE_COOKIE"}`)))
	if w.Code != 409 {
		t.Fatal("browser mode accepted Cookie import")
	}
	w = httptest.NewRecorder()
	handleAdminBrowserLogin(w, httptest.NewRequest("POST", "/admin/api/browser/login", nil))
	if w.Code != 202 || b.loginRequests.Load() != 1 {
		t.Fatal("browser login route failed")
	}
	w = httptest.NewRecorder()
	handleAdminBrowser(w, httptest.NewRequest("GET", "/admin/api/browser", nil))
	if strings.Contains(w.Body.String(), "cookie") || strings.Contains(w.Body.String(), "FAKE_COOKIE") {
		t.Fatal("browser status exposed Cookie")
	}
}

func TestBrowserHeaderAndRedirectBoundaries(t *testing.T) {
	p, err := browserParams("POST", "https://gemini.google.com/app", map[string]string{"Cookie": "FAKE_COOKIE", "Authorization": "FAKE_KEY", "Sec-Fetch-Site": "same-origin", "Origin": "FAKE_ORIGIN", "Content-Type": "text/plain"}, []byte("FAKE_PROMPT"), "binding")
	if err != nil || strings.Contains(string(p), "FAKE_COOKIE") || strings.Contains(string(p), "FAKE_KEY") {
		t.Fatal("Cookie/client API key serialized to browser script")
	}
	if _, err := trustedGoogleURL("https://accounts.google.com/redirect", browserRedirectHosts("https://gemini.google.com/request")); err == nil {
		t.Fatal("Gemini POST allowed redirect to another Google service")
	}
	if _, err := trustedGoogleURL("https://work.fife.usercontent.google.com/download", browserRedirectHosts("https://lh3.googleusercontent.com/gg-dl/fake")); err != nil {
		t.Fatal("approved media redirect blocked")
	}
}
