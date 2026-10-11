package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenCodeCLIUsesBrowserProxyAPI(t *testing.T) {
	if os.Getenv("GW2A_OPENCODE_TESTS") != "1" {
		t.Skip("opt-in installed OpenCode client smoke test")
	}
	cli, err := exec.LookPath("opencode")
	if err != nil {
		t.Skip("OpenCode not installed")
	}
	b := withMockBrowser(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-fake-opencode-only" {
			w.WriteHeader(401)
			return
		}
		handleChatCompletions(w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	dir := t.TempDir()
	config := map[string]any{"$schema": "https://opencode.ai/config.json", "model": "gemini-go-browser/gemini-3.1-pro", "small_model": "gemini-go-browser/gemini-3.1-pro", "enabled_providers": []string{"gemini-go-browser"}, "permission": map[string]string{"*": "deny"}, "share": "disabled", "provider": map[string]any{
		"gemini-go-browser": map[string]any{"npm": "@ai-sdk/openai-compatible", "name": "Fake local browser proxy", "options": map[string]string{"baseURL": server.URL + "/v1", "apiKey": "sk-fake-opencode-only"}, "models": map[string]any{"gemini-3.1-pro": map[string]any{"name": "Fake Gemini"}}},
	}}
	data, _ := json.Marshal(config)
	path := filepath.Join(dir, "opencode.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cli, "run", "--pure", "--model", "gemini-go-browser/gemini-3.1-pro", "--format", "json", "FAKE_SMOKE_INPUT")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "OPENCODE_CONFIG=" + path, "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"), "XDG_DATA_HOME=" + filepath.Join(dir, "data"), "XDG_CACHE_HOME=" + filepath.Join(dir, "cache"), "XDG_STATE_HOME=" + filepath.Join(dir, "state"), "TMPDIR=" + dir, "OPENCODE_DISABLE_AUTOUPDATE=true"}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "BROWSER_PROXY_OK") || b.calls.Load() == 0 {
		t.Fatalf("OpenCode client smoke failed: %v\n%s", err, out)
	}
	t.Log("OpenCode CLI reached /v1/chat/completions and consumed the browser-mode streaming API reply")
}
