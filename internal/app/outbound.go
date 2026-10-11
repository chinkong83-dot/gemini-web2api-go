package app

import (
	"fmt"
	"net/url"
	"strings"
)

var mediaHosts = map[string]bool{
	"lh3.googleusercontent.com":           true,
	"work.fife.usercontent.google.com":    true,
	"contribution.usercontent.google.com": true,
}

var uploadHosts = map[string]bool{
	"gemini.google.com":           true,
	"push.clients6.google.com":    true,
	"content-push.googleapis.com": true,
}

var accountHosts = map[string]bool{"accounts.google.com": true}
var geminiHosts = map[string]bool{"gemini.google.com": true}

func trustedGoogleURL(raw string, hosts map[string]bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		!hosts[strings.ToLower(u.Hostname())] || (u.Port() != "" && u.Port() != "443") {
		return nil, fmt.Errorf("blocked outbound URL: expected an approved Google HTTPS host")
	}
	return u, nil
}
