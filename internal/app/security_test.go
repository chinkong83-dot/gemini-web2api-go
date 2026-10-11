package app

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type safetyTransport func(*http.Request) (*http.Response, error)

func (f safetyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func safetyClient(t *testing.T, f safetyTransport) string {
	t.Helper()
	key := "safety-test:" + t.Name()
	stdlibClientCache.Store(key, &http.Client{Transport: f, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}})
	t.Cleanup(func() { stdlibClientCache.Delete(key) })
	return key
}

func safetyResponse(r *http.Request, status int, headers http.Header, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func safetyFrame(text string) string {
	inner, _ := json.Marshal([]interface{}{strings.Repeat("metadata", 32), nil, nil, nil,
		[]interface{}{[]interface{}{nil, []interface{}{text}}}})
	outer, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", "rpc", string(inner)}})
	return string(outer)
}

func TestTrustedGoogleURL(t *testing.T) {
	for _, raw := range []string{
		"https://lh3.googleusercontent.com/gg-dl/x", "https://LH3.GOOGLEUSERCONTENT.COM:443/gg/x",
		"https://work.fife.usercontent.google.com/rd-gg-dl/x", "https://contribution.usercontent.google.com/download?c=x",
	} {
		if _, err := trustedGoogleURL(raw, mediaHosts); err != nil {
			t.Errorf("blocked known Google URL %q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"https://attacker.invalid/lh3.googleusercontent.com/gg-dl/x",
		"https://lh3.googleusercontent.com.attacker.invalid/gg/x",
		"https://lh3.googleusercontent.com@attacker.invalid/gg/x",
		"https://user:FAKE_PASSWORD@lh3.googleusercontent.com/gg/x",
		"http://lh3.googleusercontent.com/gg/x", "//lh3.googleusercontent.com/gg/x",
		"https://lh3.googleusercontent.com:8443/gg/x", "https://lh3.googleusercontent.com./gg/x",
		"https://127.0.0.1/gg/x", "https://[::1]/gg/x", "https://accounts.google.com/gg/x",
		"file:///tmp/lh3.googleusercontent.com/gg/x", "%", "",
	} {
		if _, err := trustedGoogleURL(raw, mediaHosts); err == nil {
			t.Errorf("accepted untrusted URL %q", raw)
		} else if strings.Contains(err.Error(), raw) && raw != "" {
			t.Errorf("error echoed sensitive URL %q", raw)
		}
	}
}

func TestMediaURLSelectionUsesHostAndPath(t *testing.T) {
	valid := "https://lh3.googleusercontent.com/gg-dl/token"
	if got := collectImageURLs(safetyFrame(valid)); len(got) != 1 || got[0] != valid {
		t.Fatalf("valid image URL not selected: %v", got)
	}
	for _, raw := range []string{
		"https://attacker.invalid/lh3.googleusercontent.com/gg-dl/fake",
		"https://lh3.googleusercontent.com.attacker.invalid/gg/fake",
		"see https://lh3.googleusercontent.com/gg/fake",
		"https://lh3.googleusercontent.com/other?url=lh3.googleusercontent.com/gg/fake",
	} {
		if got := collectImageURLs(safetyFrame(raw)); len(got) != 0 {
			t.Errorf("selected unsafe or non-artifact string %q: %v", raw, got)
		}
	}
	valid = "https://contribution.usercontent.google.com/download?c=x"
	if got := collectDownloadURLs(safetyFrame(valid)); len(got) != 1 {
		t.Fatalf("valid download URL not selected: %v", got)
	}
	if got := collectDownloadURLs(safetyFrame("https://attacker.invalid/contribution.usercontent.google.com/download?c=x")); len(got) != 0 {
		t.Fatal("selected foreign download host")
	}
}

func TestCookieNeverFollowsUnsafeMediaRedirect(t *testing.T) {
	for _, target := range []string{"https://attacker.invalid/capture", "http://work.fife.usercontent.google.com/capture", "https://work.fife.usercontent.google.com:8443/capture"} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			proxy := safetyClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				return safetyResponse(r, 302, http.Header{"Location": {target}}, ""), nil
			})
			_, _, _, err := mediaGetFollow("https://lh3.googleusercontent.com/gg-dl/fake", map[string]string{"Cookie": "SID=FAKE_SESSION"}, proxy)
			if err == nil || calls != 1 {
				t.Fatalf("unsafe redirect sent a request: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestAllowedGoogleMediaRedirectRetainsCookie(t *testing.T) {
	calls := 0
	proxy := safetyClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Cookie") != "SID=FAKE_SESSION" {
			t.Fatal("Google download lost its session cookie")
		}
		if calls == 1 {
			return safetyResponse(r, 302, http.Header{"Location": {"https://work.fife.usercontent.google.com/rd-gg-dl/fake"}}, ""), nil
		}
		return safetyResponse(r, 200, http.Header{"Content-Type": {"image/png"}}, "fake-image"), nil
	})
	_, data, err := downloadBytes("https://lh3.googleusercontent.com/gg-dl/fake", "SID=FAKE_SESSION", proxy, "image/png")
	if err != nil || calls != 2 || string(data) != "fake-image" {
		t.Fatalf("known Google redirect failed: calls=%d data=%q err=%v", calls, data, err)
	}
}

func TestCredentialRequestsRejectForeignHostsBeforeTransport(t *testing.T) {
	calls := 0
	proxy := safetyClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return safetyResponse(r, 200, http.Header{}, ""), nil
	})
	headers := map[string]string{"Cookie": "SID=FAKE_SESSION", "Authorization": "FAKE_AUTH"}
	for _, target := range []string{"https://attacker.invalid/", "http://gemini.google.com/", "https://gemini.google.com.attacker.invalid/"} {
		if _, _, _, err := mediaGetOnce(target, headers, proxy); err == nil {
			t.Fatal("unsafe media request accepted")
		}
		if _, _, _, err := uploadPost(target, headers, []byte("FAKE_FILE"), proxy); err == nil {
			t.Fatal("unsafe upload request accepted")
		}
		if _, _, _, err := rotateDo("POST", target, headers, nil, proxy); err == nil {
			t.Fatal("unsafe rotation request accepted")
		}
		if _, _, _, _, err := doGeminiRequest(target, "FAKE_PROMPT", headers, proxy, nil); err == nil {
			t.Fatal("unsafe Gemini request accepted")
		}
	}
	if calls != 0 {
		t.Fatalf("credential request reached transport %d times", calls)
	}
}

func TestInlineMediaRejectsRemoteAndLocalURLs(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1/admin/api/apikey", "http://169.254.169.254/latest/meta-data/", "https://example.invalid/image.png", "file:///tmp/private"} {
		if _, err := materializeImage(target, "", 1); err == nil {
			t.Errorf("unsafe source accepted: %q", target)
		}
	}
	u, err := materializeImage("data:image/png;base64,ZmFrZQ==", "", 1)
	if err != nil || string(u.Data) != "fake" || u.Kind != 1 {
		t.Fatalf("inline image failed: %+v %v", u, err)
	}
	u, err = materializeImage("data:video/mp4;base64,ZmFrZQ==", "", 1)
	if err != nil || string(u.Data) != "fake" || u.Kind != 2 {
		t.Fatalf("inline video failed: %+v %v", u, err)
	}
}

func TestUploadRejectsInjectedFinalizeURL(t *testing.T) {
	const cookie = "SAPISID=FAKE_UPLOAD; SID=FAKE_SESSION"
	key := cookieKey(cookie)
	xsrfMu.Lock()
	xsrfCache[key] = xsrfEntry{token: "FAKE_XSRF", pushID: "FAKE_PUSH", fetched: time.Now()}
	xsrfMu.Unlock()
	t.Cleanup(func() { invalidateXSRF(cookie) })
	calls := 0
	proxy := safetyClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Hostname() != "push.clients6.google.com" || r.Header.Get("Cookie") != cookie {
			t.Fatal("unexpected upload destination or session")
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "FAKE_PRIVATE_FILE") {
			t.Fatal("file contents sent before upload URL validation")
		}
		return safetyResponse(r, 200, http.Header{"X-Goog-Upload-Url": {"https://attacker.invalid/upload"}}, ""), nil
	})
	if _, err := uploadBytes(cookie, proxy, []byte("FAKE_PRIVATE_FILE"), "test.txt"); err == nil || calls != 1 {
		t.Fatalf("unsafe finalize URL was used: calls=%d err=%v", calls, err)
	}
}

func TestRequireLoginRejectsExpiredCookieWithoutAnonymousPrompt(t *testing.T) {
	resetSeedState(t)
	old := cfg.RequireLogin
	cfg.RequireLogin = true
	t.Cleanup(func() { cfg.RequireLogin = old })
	rtMu.Lock()
	oldRT := rtVal
	rtVal.GeminiBLAuto, rtVal.FallbackAnon = false, true
	rtMu.Unlock()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRT; rtMu.Unlock() })
	const proxyURL = "http://127.0.0.1:18888"
	pid, err := proxyCreate("fake exit", proxyURL, 1)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	stdlibClientCache.Store(proxyURL, &http.Client{Transport: safetyTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		if r.Method != "GET" || len(body) != 0 {
			t.Fatalf("expired account sent a prompt: method=%s body=%q", r.Method, body)
		}
		return safetyResponse(r, 200, http.Header{}, "not signed in"), nil
	})})
	t.Cleanup(func() { stdlibClientCache.Delete(proxyURL) })
	id, err := accountAdd("expired", "SAPISID=FAKE_EXPIRED; SID=FAKE_SESSION", "")
	if err != nil {
		t.Fatal(err)
	}
	bindAccountProxy(id, pid)
	mc := Models["gemini-3.6-flash"]
	if _, err := streamGenerateWithFiles("FAKE_PROMPT", "FAKE_PROMPT", mc, nil, nil, nil); err == nil {
		t.Fatal("expired login fell back to an anonymous request")
	}
	if _, _, _, err := callGeminiConv([]map[string]interface{}{{"role": "user", "content": "FAKE_PROMPT"}}, mc, nil, nil, nil, nil); err == nil {
		t.Fatal("multi-turn expired login fell back to anonymous")
	}
	if res := probeGemini("FAKE_PROMPT", proxyURL); res.Status != "login_required" {
		t.Fatalf("diagnostic sent a prompt without a valid login: %+v", res)
	}
	if calls == 0 {
		t.Fatal("test did not exercise login verification")
	}
}

func TestRequireLoginBlocksEmptyAndDisabledPool(t *testing.T) {
	resetSeedState(t)
	old := cfg.RequireLogin
	cfg.RequireLogin = true
	t.Cleanup(func() { cfg.RequireLogin = old })
	rtMu.Lock()
	oldRT := rtVal
	rtVal.AnonFirst, rtVal.FallbackAnon = true, true
	rtMu.Unlock()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRT; rtMu.Unlock() })
	mc := Models["gemini-3.6-flash"]
	if anonFirstEligible(mc, false) {
		t.Fatal("require_login allowed anon_first")
	}
	check := func() {
		t.Helper()
		if _, err := streamGenerateWithFiles("FAKE_PROMPT", "FAKE_PROMPT", mc, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "login required") {
			t.Fatalf("single turn did not fail before sending: %v", err)
		}
		if _, err := streamGenerateConv("FAKE_PROMPT", mc, &convState{}, nil, nil); err == nil {
			t.Fatal("anonymous conversation accepted")
		}
		if _, _, _, err := callGeminiConv([]map[string]interface{}{{"role": "user", "content": "FAKE_PROMPT"}}, mc, nil, nil, nil, nil); err == nil {
			t.Fatal("multi-turn empty pool accepted")
		}
		if res := probeGemini("FAKE_PROMPT", ""); res.Status != "login_required" {
			t.Fatalf("diagnostic allowed anonymous prompt: %+v", res)
		}
	}
	check()
	id, err := accountAdd("fake", "SAPISID=FAKE_SAPISID; SID=FAKE_SESSION", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := accountSetStatus(id, "disabled"); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestLocalDefaultsAndAdminAuth(t *testing.T) {
	t.Setenv("SQL_DSN", "")
	c := defaultConfig()
	if c.Host != "127.0.0.1" || !c.RequireLogin || validateStartupConfig(c) == nil {
		t.Fatalf("unsafe startup defaults: %+v", c)
	}
	c.AdminToken = "FAKE_LOCAL_ADMIN"
	if err := validateStartupConfig(c); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SQL_DSN", "postgres://fake:FAKE_PASSWORD@example.invalid/db")
	if err := validateStartupConfig(c); err == nil || strings.Contains(err.Error(), "FAKE_PASSWORD") {
		t.Fatalf("remote storage was accepted or exposed its credentials: %v", err)
	}
	old := cfg.AdminToken
	cfg.AdminToken = ""
	t.Cleanup(func() { cfg.AdminToken = old })
	r := httptest.NewRequest("GET", "http://localhost/admin/api/apikey", nil)
	if authOK(r) {
		t.Fatal("empty admin token authorized request")
	}
	w := httptest.NewRecorder()
	handleAdminLogin(w, httptest.NewRequest("POST", "http://localhost/admin/api/login", strings.NewReader(`{"token":""}`)))
	if w.Code != 401 {
		t.Fatal("empty token created an admin session")
	}
	cfg.AdminToken = "FAKE_LOCAL_ADMIN"
	r = httptest.NewRequest("GET", "http://localhost/admin/api/apikey?token=FAKE_LOCAL_ADMIN", nil)
	if authOK(r) {
		t.Fatal("query token authorized request")
	}
	r.Header.Set("Authorization", "Bearer FAKE_LOCAL_ADMIN")
	if !authOK(r) {
		t.Fatal("Bearer admin token rejected")
	}
	for _, secure := range []bool{false, true} {
		r := httptest.NewRequest("POST", "http://localhost/admin/api/login", strings.NewReader(`{"token":"FAKE_LOCAL_ADMIN"}`))
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		handleAdminLogin(w, r)
		cookies := w.Result().Cookies()
		if w.Code != 200 || len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].Secure != secure {
			t.Fatalf("invalid session cookie over TLS=%v", secure)
		}
	}
}

func TestSQLiteCredentialsFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	base := filepath.Join(t.TempDir(), "private", "gemini.db")
	if err := prepareSQLiteFile(base); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.WriteFile(base+suffix, []byte("FAKE_STORAGE"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(base+suffix, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareSQLiteFile(base); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(base + suffix)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe SQLite permissions for suffix %q", suffix)
		}
	}
	info, _ := os.Stat(filepath.Dir(base))
	if info.Mode().Perm() != 0o700 {
		t.Fatal("new credentials directory is not private")
	}
	link := filepath.Join(t.TempDir(), "link.db")
	if err := os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareSQLiteFile(link); err == nil {
		t.Fatal("SQLite symlink accepted")
	}
}
