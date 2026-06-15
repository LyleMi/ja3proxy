package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func replaceDefaultTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()

	original := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() {
		http.DefaultTransport = original
	})
}

func TestMatchingProtocols(t *testing.T) {
	tests := []struct {
		name      string
		supported []string
		allowed   []string
		want      []string
	}{
		{
			name:      "keeps supported order",
			supported: []string{"h2", "http/1.1", "h3"},
			allowed:   []string{"http/1.1", "h2"},
			want:      []string{"h2", "http/1.1"},
		},
		{
			name:      "no overlap",
			supported: []string{"h3"},
			allowed:   []string{"h2", "http/1.1"},
			want:      []string{},
		},
		{
			name:      "empty allowed",
			supported: []string{"h2"},
			allowed:   nil,
			want:      []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchingProtocols(tt.supported, tt.allowed); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("matchingProtocols() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpstreamALPN(t *testing.T) {
	if got := upstreamALPN(nil); !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("upstreamALPN(nil) = %v, want [http/1.1]", got)
	}

	input := []string{"h2", "http/1.1"}
	if got := upstreamALPN(input); !reflect.DeepEqual(got, input) {
		t.Fatalf("upstreamALPN(%v) = %v, want %v", input, got, input)
	}
}

func TestClientALPN(t *testing.T) {
	if got := clientALPN(""); !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("clientALPN(\"\") = %v, want [http/1.1]", got)
	}

	if got := clientALPN("h2"); !reflect.DeepEqual(got, []string{"h2"}) {
		t.Fatalf("clientALPN(\"h2\") = %v, want [h2]", got)
	}
}

func TestLimitSpecALPN(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1", "h3"}},
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2", "h3"}},
		},
	}

	limitSpecALPN(spec, []string{"http/1.1"})

	if len(spec.Extensions) != 2 {
		t.Fatalf("extension count after filtering = %d, want 2", len(spec.Extensions))
	}

	alpn, ok := spec.Extensions[1].(*utls.ALPNExtension)
	if !ok {
		t.Fatalf("extension[1] = %T, want *utls.ALPNExtension", spec.Extensions[1])
	}
	if !reflect.DeepEqual(alpn.AlpnProtocols, []string{"http/1.1"}) {
		t.Fatalf("ALPN protocols = %v, want [http/1.1]", alpn.AlpnProtocols)
	}
}

func TestCopyHeader(t *testing.T) {
	src := http.Header{}
	src.Add("Set-Cookie", "a=1")
	src.Add("Set-Cookie", "b=2")
	src.Set("Content-Type", "text/plain")

	dst := http.Header{}
	copyHeader(dst, src)

	if got := dst.Values("Set-Cookie"); !reflect.DeepEqual(got, []string{"a=1", "b=2"}) {
		t.Fatalf("copied Set-Cookie values = %v, want [a=1 b=2]", got)
	}
	if got := dst.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("copied Content-Type = %q, want text/plain", got)
	}
}

func TestHandleHTTPWritesUpstreamResponse(t *testing.T) {
	var upstreamReq *http.Request
	replaceDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamReq = req
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header: http.Header{
				"Content-Type": {"text/plain"},
				"Set-Cookie":   {"a=1", "b=2"},
				"X-Test":       {"ok"},
			},
			Body: io.NopCloser(strings.NewReader("proxied body")),
		}, nil
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	req.RequestURI = "http://example.com/resource"
	rec := httptest.NewRecorder()

	handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
	if got := resp.Header.Values("Set-Cookie"); !reflect.DeepEqual(got, []string{"a=1", "b=2"}) {
		t.Fatalf("Set-Cookie values = %v, want [a=1 b=2]", got)
	}
	if got := resp.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("X-Test = %q, want ok", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if got := string(body); got != "proxied body" {
		t.Fatalf("body = %q, want proxied body", got)
	}
	if upstreamReq == nil {
		t.Fatal("RoundTrip was not called")
	}
	if upstreamReq.RequestURI != "" {
		t.Fatalf("upstream RequestURI = %q, want empty", upstreamReq.RequestURI)
	}
}

func TestHandleHTTPRoundTripErrorReturnsServiceUnavailable(t *testing.T) {
	replaceDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("upstream unavailable")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	rec := httptest.NewRecorder()

	handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "upstream unavailable") {
		t.Fatalf("body = %q, want upstream error", string(body))
	}
}
