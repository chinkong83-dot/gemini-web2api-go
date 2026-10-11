package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

var browserGoogleHosts = map[string]bool{
	"gemini.google.com": true, "accounts.google.com": true,
	"push.clients6.google.com": true, "content-push.googleapis.com": true,
	"lh3.googleusercontent.com": true, "work.fife.usercontent.google.com": true,
	"contribution.usercontent.google.com": true,
}

func browserRedirectHosts(rawURL string) map[string]bool {
	u, err := trustedGoogleURL(rawURL, browserGoogleHosts)
	if err != nil {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if mediaHosts[host] {
		return mediaHosts
	}
	if host == "gemini.google.com" {
		return geminiHosts
	}
	if accountHosts[host] {
		return accountHosts
	}
	return uploadHosts
}

const browserFetchJS = `(p => {
 const send = x => globalThis[p.binding](JSON.stringify(x));
 const controller = new AbortController();
 globalThis[p.binding + '_abort'] = () => controller.abort();
 (async () => {
  try {
   const u = new URL(p.url);
   if (u.hostname === 'gemini.google.com') {
    const match = document.cookie.match(/(?:^|;\s*)SAPISID=([^;]+)/);
    if (match) {
     const ts = Math.floor(Date.now()/1000);
     const bytes = new TextEncoder().encode(ts + ' ' + match[1] + ' https://gemini.google.com');
     const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-1',bytes)),x=>x.toString(16).padStart(2,'0')).join('');
     p.headers.Authorization = 'SAPISIDHASH ' + ts + '_' + hash;
    }
   }
   const opaque = p.method === 'GET' && u.hostname !== 'gemini.google.com';
   const opts = {method:p.method, headers:opaque ? {} : p.headers, credentials:'include',
     mode:opaque ? 'no-cors' : 'cors', redirect:'follow', cache:'no-store', signal:controller.signal};
   if (p.method !== 'GET' && p.method !== 'HEAD') {
    opts.body = Uint8Array.from(atob(p.body || ''),c=>c.charCodeAt(0));
   }
   const response = await fetch(p.url,opts);
   if (response.body) {
    const reader = response.body.getReader(), decoder = new TextDecoder();
    while (true) {
     const {done,value} = await reader.read();
     if (done) break;
     send({kind:'chunk',text:decoder.decode(value,{stream:true})});
    }
    const tail=decoder.decode(); if(tail) send({kind:'chunk',text:tail});
   }
   send({kind:'done'});
  } catch (_) { send({kind:'error'}); }
 })();
 return true;
})`

func (b *chromeSession) Request(method, rawURL string, headers map[string]string, body []byte, onLine func(string)) (browserReply, error) {
	if _, err := trustedGoogleURL(rawURL, browserGoogleHosts); err != nil {
		return browserReply{}, err
	}
	if !b.Ready() {
		return browserReply{}, fmt.Errorf("Google browser login required")
	}
	seconds := rtCfg().RequestTimeout
	if seconds <= 0 {
		seconds = 180
	}
	queue, stopQueue := context.WithTimeout(b.root, time.Duration(seconds)*time.Second)
	defer stopQueue()
	if err := b.lock(queue); err != nil {
		return browserReply{}, err
	}
	defer b.unlock()
	deadline, _ := queue.Deadline()
	ctx, cancel := context.WithDeadline(b.ctx, deadline)
	defer cancel()
	if _, err := b.snapshotLocked(ctx); err != nil {
		b.Login()
		return browserReply{}, err
	}
	urlJSON, _ := json.Marshal(rawURL)
	canonical, err := chromedp.Run(ctx, chromedp.Evaluate[string](`(() => { const u=new URL(`+string(urlJSON)+`); u.hash=''; return u.href; })()`))
	if err != nil {
		return browserReply{}, fmt.Errorf("Chrome URL normalization failed")
	}
	rawURL = canonical
	target := chromedp.FromContext(b.ctx).Target
	binding := "gw2a_" + randHex(12)
	params, err := browserParams(method, rawURL, headers, body, binding)
	if err != nil {
		return browserReply{}, err
	}
	paused, cancelPaused := target.Subscribe(fetch.RequestPaused.Method)
	responses, cancelResponses := target.Subscribe(network.ResponseReceived.Method)
	finished, cancelFinished := target.Subscribe(network.LoadingFinished.Method)
	failed, cancelFailed := target.Subscribe(network.LoadingFailed.Method)
	bindings, cancelBindings := target.Subscribe(runtime.BindingCalled.Method)
	defer cancelPaused()
	defer cancelResponses()
	defer cancelFinished()
	defer cancelFailed()
	defer cancelBindings()
	defer func() {
		cleanup, done := context.WithTimeout(b.ctx, 3*time.Second)
		defer done()
		_, _ = chromedp.Run(cleanup, chromedp.Evaluate[chromedp.Void](fmt.Sprintf(`(() => { const f=globalThis[%q]; if(f) f(); delete globalThis[%q]; delete globalThis[%q]; })()`, binding+"_abort", binding+"_abort", binding)))
		_, _ = cdp.Call(cleanup, target, runtime.RemoveBinding, runtime.RemoveBindingParams{Name: binding})
		_, _ = cdp.Call(cleanup, target, fetch.Disable, cdp.Empty{})
	}()
	maxBody := int64(128 << 20)
	noPostData := int64(0)
	if _, err = cdp.Call(ctx, target, network.Enable, network.EnableParams{MaxTotalBufferSize: &maxBody, MaxResourceBufferSize: &maxBody, MaxPostDataSize: &noPostData}); err != nil {
		return browserReply{}, fmt.Errorf("Chrome network initialization failed")
	}
	if _, err = cdp.Call(ctx, target, runtime.AddBinding, runtime.AddBindingParams{Name: binding}); err != nil {
		return browserReply{}, fmt.Errorf("Chrome stream initialization failed")
	}
	if _, err = cdp.Call(ctx, target, fetch.Enable, fetch.EnableParams{Patterns: []*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}}}); err != nil {
		return browserReply{}, fmt.Errorf("Chrome destination guard failed")
	}
	if _, err = chromedp.Run(ctx, chromedp.Evaluate[chromedp.Void](browserFetchJS+"("+string(params)+")")); err != nil {
		return browserReply{}, fmt.Errorf("Chrome request initialization failed")
	}
	var networkID network.RequestID
	redirectHosts := browserRedirectHosts(rawURL)
	selected := map[fetch.RequestID]bool{}
	var reply browserReply
	var bodyDone, jsDone bool
	var lineBuffer string
	started := time.Now()
	for {
		if bodyDone && jsDone && reply.Status != 0 {
			if (reply.Status == 401 || reply.Status == 403) && geminiHosts[rawURLHost(rawURL)] {
				b.ready.Store(false)
				b.Login()
			}
			if lineBuffer != "" && onLine != nil {
				onLine(lineBuffer)
			}
			return reply, nil
		}
		select {
		case <-ctx.Done():
			return browserReply{}, fmt.Errorf("Chrome request timed out or browser closed")
		case raw, ok := <-paused:
			if !ok {
				return browserReply{}, fmt.Errorf("Chrome closed during request")
			}
			var e fetch.EventRequestPaused
			if json.Unmarshal(raw, &e) != nil || e.Request == nil {
				return browserReply{}, fmt.Errorf("invalid Chrome request event")
			}
			mine := selected[e.RedirectedRequestID] || (networkID != "" && e.NetworkID == networkID) ||
				(networkID == "" && e.Request.URL == rawURL && e.Request.Method == method)
			if mine {
				selected[e.RequestID] = true
				if len(selected) > 6 {
					_, _ = cdp.Call(ctx, target, fetch.FailRequest, fetch.FailRequestParams{RequestID: e.RequestID, ErrorReason: network.ErrorReasonBlockedByClient})
					return browserReply{}, fmt.Errorf("Google browser redirect limit exceeded")
				}
				if networkID == "" {
					networkID = e.NetworkID
				}
				if _, err := trustedGoogleURL(e.Request.URL, redirectHosts); err != nil {
					_, _ = cdp.Call(ctx, target, fetch.FailRequest, fetch.FailRequestParams{RequestID: e.RequestID, ErrorReason: network.ErrorReasonBlockedByClient})
					return browserReply{}, err
				}
			}
			if _, err := cdp.Call(ctx, target, fetch.ContinueRequest, fetch.ContinueRequestParams{RequestID: e.RequestID}); err != nil {
				return browserReply{}, fmt.Errorf("Chrome request continuation failed")
			}
		case raw, ok := <-responses:
			if !ok {
				return browserReply{}, fmt.Errorf("Chrome closed during request")
			}
			var e network.EventResponseReceived
			if json.Unmarshal(raw, &e) != nil || e.Response == nil || e.RequestID != networkID {
				continue
			}
			reply.Status = int(e.Response.Status)
			reply.TTFB = time.Since(started).Milliseconds()
			reply.Headers = map[string]string{}
			for k, v := range e.Response.Headers {
				low := strings.ToLower(k)
				if low == "set-cookie" || low == "cookie" {
					continue
				}
				reply.Headers[low] = fmt.Sprint(v)
			}
		case raw, ok := <-finished:
			if !ok {
				return browserReply{}, fmt.Errorf("Chrome closed during request")
			}
			var e network.EventLoadingFinished
			if json.Unmarshal(raw, &e) != nil || e.RequestID != networkID {
				continue
			}
			if e.EncodedDataLength > float64(maxBody) {
				return browserReply{}, fmt.Errorf("Google browser response exceeds 128 MiB")
			}
			result, err := cdp.Call(ctx, target, network.GetResponseBody, network.GetResponseBodyParams{RequestID: e.RequestID})
			if err != nil {
				return browserReply{}, fmt.Errorf("Chrome response body is unavailable")
			}
			if len(result.Body) > int(maxBody) {
				return browserReply{}, fmt.Errorf("Google browser response exceeds 128 MiB")
			}
			reply.Body = result.Body
			bodyDone = true
		case raw, ok := <-failed:
			if !ok {
				return browserReply{}, fmt.Errorf("Chrome closed during request")
			}
			var e network.EventLoadingFailed
			if json.Unmarshal(raw, &e) == nil && e.RequestID == networkID {
				return browserReply{}, fmt.Errorf("Chrome could not complete the Google request")
			}
		case raw, ok := <-bindings:
			if !ok {
				return browserReply{}, fmt.Errorf("Chrome closed during request")
			}
			var e runtime.EventBindingCalled
			if json.Unmarshal(raw, &e) != nil || e.Name != binding {
				continue
			}
			var msg struct {
				Kind string `json:"kind"`
				Text string `json:"text"`
			}
			if json.Unmarshal([]byte(e.Payload), &msg) != nil {
				return browserReply{}, fmt.Errorf("invalid Chrome stream message")
			}
			switch msg.Kind {
			case "error":
				return browserReply{}, fmt.Errorf("Chrome fetch failed; check Google login and browser compatibility")
			case "done":
				jsDone = true
			case "chunk":
				if onLine == nil {
					continue
				}
				lineBuffer += msg.Text
				if len(lineBuffer) > int(maxBody) {
					return browserReply{}, fmt.Errorf("Google browser stream exceeds 128 MiB")
				}
				for {
					i := strings.IndexByte(lineBuffer, '\n')
					if i < 0 {
						break
					}
					onLine(lineBuffer[:i])
					lineBuffer = lineBuffer[i+1:]
				}
			}
		}
	}
}

func rawURLHost(rawURL string) string {
	u, err := trustedGoogleURL(rawURL, browserGoogleHosts)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
