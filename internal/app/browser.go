package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/chromedp"
)

const browserSessionMarker = "browser-managed-session"

type browserReply struct {
	Status  int
	Headers map[string]string
	Body    []byte
	TTFB    int64
}

type browserInfo struct {
	Enabled     bool `json:"enabled"`
	Ready       bool `json:"ready"`
	Visible     bool `json:"visible"`
	ShowBrowser bool `json:"show_browser"`
	LoggingIn   bool `json:"logging_in"`
}

type browserGateway interface {
	Ready() bool
	Snapshot() (string, error)
	Refresh() error
	Request(string, string, map[string]string, []byte, func(string)) (browserReply, error)
	Status() browserInfo
	Login()
	Close()
}

var browserMu sync.RWMutex
var activeBrowser browserGateway

func currentBrowser() browserGateway {
	browserMu.RLock()
	defer browserMu.RUnlock()
	return activeBrowser
}

func setBrowser(b browserGateway) {
	browserMu.Lock()
	activeBrowser = b
	browserMu.Unlock()
}

func browserReady() bool {
	b := currentBrowser()
	return b != nil && b.Ready()
}

func googleLoginRequiredError() error {
	if cfg.BrowserEnabled {
		return fmt.Errorf("Google browser login required; complete SSO in the Chrome window")
	}
	return fmt.Errorf("Google login required: add an enabled account cookie in the admin panel")
}

func browserRequest(method, rawURL string, headers map[string]string, body []byte, onLine func(string)) (browserReply, error) {
	b := currentBrowser()
	if b == nil || !b.Ready() {
		return browserReply{}, fmt.Errorf("Google browser login required; sign in in the Chrome window")
	}
	return b.Request(method, rawURL, cleanBrowserHeaders(headers), body, onLine)
}

func showBrowserEnv() (bool, error) {
	raw := os.Getenv("GEMINI_SHOW_BROWSER")
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("GEMINI_SHOW_BROWSER must be 0/1 or false/true")
	}
	return v, nil
}

func defaultBrowserProfile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "gemini-web2api-go", "chrome-profile")
}

func prepareBrowserProfile(dir string) error {
	if dir == "" {
		return fmt.Errorf("browser profile directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("browser profile must be a dedicated directory")
	}
	marker := filepath.Join(dir, ".gw2a-profile")
	if _, err := os.Stat(marker); os.IsNotExist(err) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("use an empty dedicated browser profile, not an existing personal/company Chrome profile")
		}
		if err := os.WriteFile(marker, []byte("gemini-web2api-go\n"), 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

type chromeSession struct {
	root                      context.Context
	stop                      context.CancelFunc
	serial                    chan struct{}
	ctx                       context.Context
	cancel                    context.CancelFunc
	allocCancel               context.CancelFunc
	profile, chromePath       string
	show                      bool
	ready, visible, loggingIn atomic.Bool
	closed                    atomic.Bool
	extraOptions              []chromedp.ExecAllocatorOption
}

func newChromeSession(profile, chromePath string, show bool) (*chromeSession, error) {
	if err := prepareBrowserProfile(profile); err != nil {
		return nil, err
	}
	root, stop := context.WithCancel(context.Background())
	b := &chromeSession{root: root, stop: stop, serial: make(chan struct{}, 1), profile: profile, chromePath: chromePath, show: show}
	b.serial <- struct{}{}
	return b, nil
}

func (b *chromeSession) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.serial:
		return nil
	}
}
func (b *chromeSession) unlock()     { b.serial <- struct{}{} }
func (b *chromeSession) Ready() bool { return b.ready.Load() && !b.closed.Load() }
func (b *chromeSession) Status() browserInfo {
	return browserInfo{Enabled: true, Ready: b.Ready(), Visible: b.visible.Load(), ShowBrowser: b.show, LoggingIn: b.loggingIn.Load()}
}

func (b *chromeSession) launchLocked(visible bool) error {
	if b.closed.Load() {
		return fmt.Errorf("browser is closed")
	}
	if b.cancel != nil {
		_ = chromedp.Cancel(b.ctx)
		b.cancel()
		b.allocCancel()
	}
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.UserDataDir(b.profile), chromedp.Flag("headless", !visible),
		chromedp.Flag("enable-automation", false), chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-extensions", true))
	if b.chromePath != "" {
		opts = append(opts, chromedp.ExecPath(b.chromePath))
	}
	opts = append(opts, b.extraOptions...)
	alloc, allocCancel := chromedp.NewExecAllocator(b.root, opts...)
	ctx, cancel := chromedp.NewContext(alloc, chromedp.WithLogf(func(string, ...any) {}), chromedp.WithErrorf(func(string, ...any) {}))
	b.ctx, b.cancel, b.allocCancel = ctx, cancel, allocCancel
	b.visible.Store(visible)
	if _, err := chromedp.Run(ctx, chromedp.Evaluate[chromedp.Void]("void 0")); err != nil {
		cancel()
		allocCancel()
		return fmt.Errorf("cannot start Chrome; install Chrome or set --chrome-path")
	}
	boot, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	if _, err := chromedp.Run(boot, chromedp.Navigate("https://gemini.google.com/app")); err != nil {
		cancel()
		allocCancel()
		return fmt.Errorf("cannot start Chrome; install Chrome or set --chrome-path")
	}
	return nil
}

const browserSnapshotJS = `(() => {
 const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
 const editor = document.querySelector('rich-textarea .ql-editor');
 const account = document.querySelector('a[href^="https://accounts.google.com/SignOutOptions"]');
 const html = document.documentElement.outerHTML;
 const ready = location.origin === 'https://gemini.google.com' && visible(account) && visible(editor) &&
   editor.getAttribute('contenteditable') === 'true' && /"SNlM0e":"[^"]{10,200}"/.test(html);
 return {ready, html: ready ? html : ''};
})()`

func (b *chromeSession) snapshotLocked(ctx context.Context) (string, error) {
	type snapshotState struct {
		Ready bool   `json:"ready"`
		HTML  string `json:"html"`
	}
	state, err := chromedp.Run(ctx, chromedp.Evaluate[snapshotState](browserSnapshotJS))
	if err != nil {
		b.ready.Store(false)
		return "", fmt.Errorf("Google browser session is unavailable")
	}
	b.ready.Store(state.Ready)
	if !state.Ready {
		return "", fmt.Errorf("Google browser login required; complete SSO in Chrome")
	}
	return state.HTML, nil
}

func (b *chromeSession) Login() {
	if b.closed.Load() || !b.loggingIn.CompareAndSwap(false, true) {
		return
	}
	b.ready.Store(false)
	go func() {
		defer b.loggingIn.Store(false)
		waitCtx, done := context.WithTimeout(b.root, 10*time.Minute)
		defer done()
		if err := b.lock(waitCtx); err != nil {
			return
		}
		if b.ctx == nil || b.ctx.Err() != nil {
			if err := b.launchLocked(b.show); err != nil {
				b.unlock()
				fmt.Fprintln(os.Stderr, err)
				return
			}
		} else {
			nav, done := context.WithTimeout(b.ctx, 30*time.Second)
			_, _ = chromedp.Run(nav, chromedp.Navigate("https://gemini.google.com/app"))
			done()
		}
		probe, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		err := b.waitReadyLocked(probe)
		cancel()
		if err != nil && !b.visible.Load() {
			if err = b.launchLocked(true); err != nil {
				b.unlock()
				fmt.Fprintln(os.Stderr, err)
				return
			}
		}
		b.unlock()
		if !b.Ready() {
			fmt.Fprintln(os.Stderr, "[browser] Complete Google SSO in the Chrome window; API requests require login.")
		}
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if err := b.lock(waitCtx); err != nil {
				return
			}
			probe, cancel := context.WithTimeout(b.ctx, 3*time.Second)
			_, err := b.snapshotLocked(probe)
			cancel()
			if err == nil && !b.show && b.visible.Load() {
				b.ready.Store(false)
				err = b.launchLocked(false)
				if err == nil {
					probe, cancel = context.WithTimeout(b.ctx, 5*time.Second)
					_, err = b.snapshotLocked(probe)
					cancel()
				}
			}
			b.unlock()
			if err == nil {
				fmt.Fprintln(os.Stderr, "[browser] Google session ready.")
				return
			}
			select {
			case <-waitCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (b *chromeSession) waitReadyLocked(ctx context.Context) error {
	for {
		if _, err := b.snapshotLocked(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Google browser login required")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (b *chromeSession) Snapshot() (string, error) {
	if !b.Ready() {
		return "", fmt.Errorf("Google browser login required")
	}
	ctx, cancel := context.WithTimeout(b.root, 10*time.Second)
	defer cancel()
	if err := b.lock(ctx); err != nil {
		return "", err
	}
	defer b.unlock()
	pageCtx, done := context.WithTimeout(b.ctx, 5*time.Second)
	defer done()
	html, err := b.snapshotLocked(pageCtx)
	if err != nil {
		b.Login()
	}
	return html, err
}

func (b *chromeSession) Refresh() error {
	ctx, cancel := context.WithTimeout(b.root, 15*time.Second)
	defer cancel()
	if err := b.lock(ctx); err != nil {
		return err
	}
	defer b.unlock()
	pageCtx, done := context.WithTimeout(b.ctx, 10*time.Second)
	defer done()
	if _, err := chromedp.Run(pageCtx, chromedp.Navigate("https://gemini.google.com/app")); err != nil {
		b.ready.Store(false)
		b.Login()
		return fmt.Errorf("Chrome session refresh failed")
	}
	_, err := b.snapshotLocked(pageCtx)
	if err != nil {
		b.Login()
	}
	return err
}

func (b *chromeSession) Close() {
	if !b.closed.CompareAndSwap(false, true) {
		return
	}
	b.ready.Store(false)
	timer := time.AfterFunc(3*time.Second, b.stop)
	defer timer.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if b.lock(ctx) == nil {
		if b.ctx != nil {
			_ = chromedp.Cancel(b.ctx)
			b.cancel()
			b.allocCancel()
		}
		b.unlock()
	}
	b.stop()
}

func cleanBrowserHeaders(headers map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range headers {
		low := strings.ToLower(k)
		if low == "cookie" || low == "authorization" || low == "origin" || low == "referer" || low == "host" ||
			low == "user-agent" || low == "accept-encoding" || low == "content-length" || strings.HasPrefix(low, "sec-") {
			continue
		}
		out[k] = v
	}
	return out
}

func browserParams(method, rawURL string, headers map[string]string, body []byte, binding string) ([]byte, error) {
	return json.Marshal(struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    []byte            `json:"body"`
		Binding string            `json:"binding"`
	}{method, rawURL, cleanBrowserHeaders(headers), body, binding})
}
