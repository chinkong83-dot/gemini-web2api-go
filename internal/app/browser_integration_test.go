package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

const fakeBrowserPage = `<!doctype html><html><body>
<a href="https://accounts.google.com/SignOutOptions">Fake signed-in account</a>
<rich-textarea><div class="ql-editor" contenteditable="true">Fake editor</div></rich-textarea>
<script>const fakeBootstrap={"SNlM0e":"FAKE_XSRF_TOKEN_LONG","qKIAYe":"FAKE_PUSH_ID","Ylro7b":"FAKE_PCTX"};</script>
</body></html>`

func TestChromeNativeTransport(t *testing.T) {
	if os.Getenv("GW2A_BROWSER_TESTS") != "1" {
		t.Skip("set GW2A_BROWSER_TESTS=1 to test installed Chrome with fake HTTPS servers")
	}
	rtMu.Lock()
	oldRT := rtVal
	rtVal.RequestTimeout = 10
	rtMu.Unlock()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRT; rtMu.Unlock() })
	first := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	var serverMu sync.Mutex
	var postCookie, postAuth, postBody string
	var loginIssued bool
	hits := map[string]int{}
	binary := []byte{0, 255, 1, 2, 3, 4}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		serverMu.Lock()
		hits[r.Method+r.Host+r.URL.Path]++
		serverMu.Unlock()
		switch r.URL.Path {
		case "/app":
			serverMu.Lock()
			fresh := !loginIssued
			loginIssued = true
			serverMu.Unlock()
			if fresh {
				http.SetCookie(w, &http.Cookie{Name: "SID", Value: "FAKE_CHROME_HTTPONLY", Domain: ".google.com", Path: "/", Secure: true, HttpOnly: true, MaxAge: 3600})
				http.SetCookie(w, &http.Cookie{Name: "PREF", Value: "FAKE_PREF", Domain: ".google.com", Path: "/", Secure: true, MaxAge: 3600})
				http.SetCookie(w, &http.Cookie{Name: "SAPISID", Value: "FAKE_BROWSER_HASH", Domain: ".google.com", Path: "/", Secure: true, MaxAge: 3600})
			} else if c, err := r.Cookie("SID"); err != nil || c.Value != "FAKE_CHROME_HTTPONLY" {
				io.WriteString(w, "not signed in")
				return
			}
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, fakeBrowserPage)
		case "/stream":
			data, _ := io.ReadAll(r.Body)
			cookie, _ := r.Cookie("SID")
			serverMu.Lock()
			if cookie != nil {
				postCookie = cookie.Value
			}
			postAuth = r.Header.Get("Authorization")
			postBody = string(data)
			serverMu.Unlock()
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Set-Cookie", "PRIVATE_RESPONSE_COOKIE=FAKE_SECRET; Secure")
			io.WriteString(w, "first-line\n")
			w.(http.Flusher).Flush()
			close(first)
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
			io.WriteString(w, "second-line\n")
		case "/bad-redirect":
			http.Redirect(w, r, "https://attacker.invalid/capture", 307)
		case "/google-wrong-scope":
			http.Redirect(w, r, "https://accounts.google.com/capture", 307)
		case "/gg-dl/fake":
			if _, err := r.Cookie("SID"); err == nil {
				t.Error("Google Cookie was sent to a different cookie domain")
			}
			http.Redirect(w, r, "https://work.fife.usercontent.google.com/download", 302)
		case "/download":
			if c, err := r.Cookie("SID"); err != nil || c.Value != "FAKE_CHROME_HTTPONLY" {
				t.Error("Google Cookie scope was lost on approved redirect")
			}
			w.Header().Set("Content-Type", "image/png")
			w.Write(binary)
		case "/capture":
			io.WriteString(w, "this request should have been blocked")
		case "/upload/start":
			if c, err := r.Cookie("SID"); err != nil || c.Value != "FAKE_CHROME_HTTPONLY" {
				t.Error("Chrome upload lost native login Cookie")
			}
			w.Header().Set("X-Goog-Upload-Url", "https://push.clients6.google.com/upload/finalize")
		case "/upload/finalize":
			data, _ := io.ReadAll(r.Body)
			if !bytes.Equal(data, binary) {
				t.Errorf("binary upload corrupted: %v", data)
			}
			io.WriteString(w, "/fake-upload-ref")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	profile := filepath.Join(t.TempDir(), "chrome-profile")
	b, err := newChromeSession(profile, "", false)
	if err != nil {
		t.Fatal(err)
	}
	b.extraOptions = []chromedp.ExecAllocatorOption{chromedp.Flag("ignore-certificate-errors", true), chromedp.Flag("no-proxy-server", true),
		chromedp.Flag("host-resolver-rules", "MAP gemini.google.com "+u.Host+", MAP lh3.googleusercontent.com "+u.Host+", MAP work.fife.usercontent.google.com "+u.Host+", MAP accounts.google.com "+u.Host+", MAP push.clients6.google.com "+u.Host+", MAP attacker.invalid "+u.Host+", MAP * ~NOTFOUND")}
	defer b.Close()
	if err := b.launchLocked(false); err != nil {
		t.Fatal(err)
	}
	if _, err := b.snapshotLocked(b.ctx); err != nil {
		t.Fatal(err)
	}
	if b.Status().Visible {
		t.Fatal("default Chrome should be hidden")
	}
	var lines []string
	res, err := b.Request("POST", "https://gemini.google.com/stream", map[string]string{"Content-Type": "text/plain", "Cookie": "SID=SHOULD_NOT_LEAVE_GO", "Authorization": "Bearer FAKE_CLIENT_API"}, []byte("FAKE_PROMPT_BYTES"), func(line string) {
		lines = append(lines, line)
		if line == "first-line" {
			releaseOnce.Do(func() { close(release) })
		}
	})
	releaseOnce.Do(func() { close(release) })
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || string(res.Body) != "first-line\nsecond-line\n" || strings.Join(lines, "|") != "first-line|second-line" {
		t.Fatalf("incorrect streamed reply: %+v lines=%v", res, lines)
	}
	if _, ok := res.Headers["set-cookie"]; ok {
		t.Fatal("response Cookie leaked out of browser adapter")
	}
	serverMu.Lock()
	gotCookie, gotAuth, gotBody := postCookie, postAuth, postBody
	serverMu.Unlock()
	if gotCookie != "FAKE_CHROME_HTTPONLY" || !strings.HasPrefix(gotAuth, "SAPISIDHASH ") || gotBody != "FAKE_PROMPT_BYTES" {
		t.Fatalf("native Chrome auth/body failed: cookie=%q auth=%q body=%q", gotCookie, gotAuth, gotBody)
	}
	for _, path := range []string{"/bad-redirect", "/google-wrong-scope"} {
		if _, err := b.Request("POST", "https://gemini.google.com"+path, map[string]string{}, []byte("FAKE_PRIVATE_PROMPT"), nil); err == nil || !strings.Contains(err.Error(), "blocked outbound URL") {
			t.Fatal("unsafe POST redirect accepted")
		}
	}
	serverMu.Lock()
	leaked := hits["POSTaccounts.google.com/capture"] + hits["POSTattacker.invalid/capture"]
	serverMu.Unlock()
	if leaked != 0 {
		t.Fatal("prompt reached out-of-scope Google endpoint")
	}
	res, err = b.Request("GET", "https://LH3.GOOGLEUSERCONTENT.COM:443/gg-dl/fake#ignored-fragment", map[string]string{"Cookie": "SID=SHOULD_NOT_SEND"}, nil, nil)
	if err != nil || !bytes.Equal(res.Body, binary) || res.Headers["content-type"] != "image/png" {
		t.Fatalf("opaque media/redirect failed: body=%v headers=%v err=%v", res.Body, res.Headers, err)
	}
	res, err = b.Request("POST", "https://push.clients6.google.com/upload/start", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "X-Goog-Upload-Command": "start"}, []byte("File name: fake.bin"), nil)
	if err != nil || res.Headers["x-goog-upload-url"] != "https://push.clients6.google.com/upload/finalize" {
		t.Fatalf("native cross-origin upload start failed: %+v %v", res, err)
	}
	res, err = b.Request("POST", res.Headers["x-goog-upload-url"], map[string]string{"Content-Type": "application/octet-stream", "X-Goog-Upload-Command": "upload, finalize"}, binary, nil)
	if err != nil || string(res.Body) != "/fake-upload-ref" {
		t.Fatalf("native binary upload failed: %v %v", res.Body, err)
	}
	if err := b.launchLocked(true); err != nil {
		t.Fatal(err)
	}
	if _, err := b.snapshotLocked(b.ctx); err != nil {
		t.Fatal(err)
	}
	if !b.Status().Visible {
		t.Fatal("visible Chrome launch did not apply")
	}
	var persisted bool
	persisted, err = chromedp.Run(b.ctx, chromedp.Evaluate[bool](`document.cookie.includes('SAPISID=FAKE_BROWSER_HASH')`))
	if err != nil || !persisted {
		t.Fatal("dedicated profile did not persist browser login state")
	}
	if err := b.launchLocked(false); err != nil {
		t.Fatal(err)
	}
	if _, err := b.snapshotLocked(b.ctx); err != nil {
		t.Fatal(err)
	}
	if b.Status().Visible {
		t.Fatal("Chrome did not return to hidden mode")
	}
	profileInfo, _ := os.Stat(profile)
	if profileInfo.Mode().Perm() != 0o700 {
		t.Fatal("browser profile is not private")
	}
	encoded, _ := json.Marshal(b.Status())
	if strings.Contains(string(encoded), "FAKE_CHROME_HTTPONLY") {
		t.Fatal("status exposed login credentials")
	}
}

func TestChromeLoginVisibilityLifecycle(t *testing.T) {
	if os.Getenv("GW2A_BROWSER_TESTS") != "1" {
		t.Skip("opt-in installed Chrome test")
	}
	for _, show := range []bool{false, true} {
		t.Run(fmt.Sprint(show), func(t *testing.T) {
			var signedIn atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !signedIn.Load() {
					io.WriteString(w, "Fake sign-in required")
					return
				}
				http.SetCookie(w, &http.Cookie{Name: "SID", Value: "FAKE_PERSISTENT_LOGIN", Path: "/", Secure: true, HttpOnly: true, MaxAge: 3600})
				w.Header().Set("Content-Type", "text/html")
				io.WriteString(w, fakeBrowserPage)
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			b, err := newChromeSession(filepath.Join(t.TempDir(), "profile"), "", show)
			if err != nil {
				t.Fatal(err)
			}
			b.extraOptions = []chromedp.ExecAllocatorOption{chromedp.Flag("ignore-certificate-errors", true), chromedp.Flag("no-proxy-server", true), chromedp.Flag("host-resolver-rules", "MAP gemini.google.com "+u.Host+", MAP * ~NOTFOUND")}
			defer b.Close()
			b.Login()
			wait := func(condition func() bool) {
				t.Helper()
				deadline := time.Now().Add(20 * time.Second)
				for !condition() {
					if time.Now().After(deadline) {
						t.Fatalf("browser lifecycle timed out: %+v", b.Status())
					}
					time.Sleep(50 * time.Millisecond)
				}
			}
			wait(func() bool { return b.Status().Visible })
			signedIn.Store(true)
			ctx, cancel := context.WithTimeout(b.root, 10*time.Second)
			defer cancel()
			if err := b.lock(ctx); err != nil {
				t.Fatal(err)
			}
			_, err = chromedp.Run(b.ctx, chromedp.Navigate("https://gemini.google.com/app"))
			b.unlock()
			if err != nil {
				t.Fatal(err)
			}
			wait(func() bool { s := b.Status(); return s.Ready && !s.LoggingIn && s.Visible == show })
		})
	}
}
