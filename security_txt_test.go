// Copyright 2020 Containous SAS
// Copyright 2020 Traefik Labs
// Copyright 2025 Solution Libre
// Copyright 2026 Maarten van Heusden
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package traefik_plugin_security_txt_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	plugin "github.com/mmvanheusden/traefik-plugin-security-txt"
)

func TestEverything(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.EnableComment = false

	cfg.Expires = "2027-12-31T18:37:07Z"
	cfg.Contact = []string{"mailto:security@example.com", "https://example.com/contact"}
	cfg.PreferredLanguages = []string{"nl", "de", "en"}
	cfg.Policy = "https://example.com/disclosure-policy"
	cfg.Acknowledgments = "https://example.com/hall-of-fame"
	cfg.Canonical = []string{"https://example.com/.well-known/security.txt"}
	cfg.Encryption = "https://example.com/pgp-key.txt"
	cfg.Hiring = "mailto:hiring@example.com"
	cfg.Fallback = false

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := plugin.New(ctx, next, cfg, "security-txt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/.well-known/security.txt", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	wantedRes := "Contact: mailto:security@example.com\nContact: https://example.com/contact\nExpires: 2027-12-31T18:37:07Z\nPolicy: https://example.com/disclosure-policy\nEncryption: https://example.com/pgp-key.txt\nHiring: mailto:hiring@example.com\nAcknowledgments: https://example.com/hall-of-fame\nCanonical: https://example.com/.well-known/security.txt\nPreferred-Languages: nl, de, en\n"

	if !bytes.Equal([]byte(wantedRes), recorder.Body.Bytes()) {
		t.Errorf("got body %q, want %q", recorder.Body.Bytes(), wantedRes)
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("got status code %d, want %d", http.StatusOK, recorder.Code)
	}
}

func TestNewRequiresContact(t *testing.T) {
	_, err := plugin.New(context.Background(), http.NotFoundHandler(), plugin.CreateConfig(), "security-txt-plugin")
	if err == nil {
		t.Fatal("expected an error when no contact address is configured")
	}
}

func TestMinimal(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.Contact = []string{"mailto:security@example.com"}
	cfg.Expires = "2027-12-31T18:37:07Z"
	cfg.EnableComment = false

	handler, err := plugin.New(context.Background(), http.NotFoundHandler(), cfg, "security-txt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/.well-known/security.txt", nil)
	handler.ServeHTTP(recorder, req)

	want := "Contact: mailto:security@example.com\nExpires: 2027-12-31T18:37:07Z\n"
	if recorder.Body.String() != want {
		t.Errorf("got body %q, want %q", recorder.Body.String(), want)
	}
}

func TestFallback(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.Contact = []string{"mailto:security@example.com"}
	cfg.Expires = "2027-12-31T18:37:07Z"
	cfg.EnableComment = false

	handler, err := plugin.New(context.Background(), http.NotFoundHandler(), cfg, "security-txt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/security.txt", nil)
	handler.ServeHTTP(recorder, req)

	want := "Contact: mailto:security@example.com\nExpires: 2027-12-31T18:37:07Z\n"
	if recorder.Body.String() != want {
		t.Errorf("got body %q, want %q", recorder.Body.String(), want)
	}
}

func TestNoFallback(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.Contact = []string{"mailto:security@example.com"}
	cfg.Expires = "2027-12-31T18:37:07Z"
	cfg.EnableComment = false
	cfg.Fallback = false

	handler, err := plugin.New(context.Background(), http.NotFoundHandler(), cfg, "security-txt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/security.txt", nil)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Errorf("Fallback disabled, but its not returning 404.")
	}
}

func TestNotModifiedResponseIsPassedThrough(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.Contact = []string{"mailto:security@example.com"}

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNotModified)
	})
	handler, err := plugin.New(context.Background(), next, cfg, "security-txt-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/.well-known/security.txt", nil)
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNotModified {
		t.Errorf("got status code %d, want %d", recorder.Code, http.StatusNotModified)
	}
	if recorder.Body.Len() != 0 {
		t.Errorf("got body %q, want an empty body", recorder.Body.String())
	}
}

func TestLastModifiedHeader(t *testing.T) {
	for _, test := range []struct {
		name         string
		lastModified bool
		wantHeader   string
	}{
		{name: "removed by default", wantHeader: ""},
		{name: "preserved when enabled", lastModified: true, wantHeader: "Wed, 21 Oct 2015 07:28:00 GMT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := plugin.CreateConfig()
			cfg.Contact = []string{"mailto:security@example.com"}
			cfg.LastModified = test.lastModified
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
				_, _ = rw.Write([]byte("backend response"))
			})

			handler, err := plugin.New(context.Background(), next, cfg, "security-txt-plugin")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://localhost/.well-known/security.txt", nil)
			handler.ServeHTTP(recorder, req)

			if got := recorder.Header().Get("Last-Modified"); got != test.wantHeader {
				t.Errorf("got Last-Modified %q, want %q", got, test.wantHeader)
			}
		})
	}
}
