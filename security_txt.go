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

package traefik_plugin_security_txt

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	Contact            []string `json:"contact"`
	Expires            string   `json:"expires"` // TODO: validate ISO 8601
	Acknowledgments    string   `json:"acknowledgments,omitempty"`
	Canonical          []string `json:"canonical,omitempty"`
	Encryption         string   `json:"encryption,omitempty"`
	Hiring             string   `json:"hiring,omitempty"`
	Policy             string   `json:"policy,omitempty"`
	PreferredLanguages []string `json:"preferredLanguages,omitempty"` // TODO: validate RFC 5646

	Overwrite     bool `json:"overwrite,omitempty"`
	LastModified  bool `json:"lastModified,omitempty"`
	EnableComment bool `json:"enableComment,omitempty"`
	Fallback      bool `json:"fallback,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Overwrite:     true,
		LastModified:  false,
		EnableComment: true,
		Fallback:      true,
	}
}

type responseWriter struct {
	buffer       bytes.Buffer
	lastModified bool
	wroteHeader  bool

	http.ResponseWriter
	backendStatusCode int
	statusCode        int
}

type SecurityTxtPlugin struct {
	contact            []string
	expires            string
	acknowledgments    *string
	canonical          []string
	encryption         *string
	hiring             *string
	policy             *string
	preferredLanguages []string

	overwrite     bool
	lastModified  bool
	enableComment bool
	fallback      bool

	next http.Handler
}

// Helper to convert an empty string into a nil pointer
func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Contact) == 0 {
		return nil, fmt.Errorf("Configure at least one contact address.")
	}

	return &SecurityTxtPlugin{
		contact:            config.Contact,
		expires:            config.Expires,
		acknowledgments:    optString(config.Acknowledgments),
		canonical:          config.Canonical,
		encryption:         optString(config.Encryption),
		hiring:             optString(config.Hiring),
		policy:             optString(config.Policy),
		preferredLanguages: config.PreferredLanguages,
		fallback:           config.Fallback,

		overwrite:     config.Overwrite,
		lastModified:  config.LastModified,
		enableComment: config.EnableComment,

		next: next,
	}, nil
}

func (p *SecurityTxtPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if strings.ToLower(req.URL.Path) != "/.well-known/security.txt" && !(p.fallback && strings.ToLower(req.URL.Path) == "/security.txt") {
		p.next.ServeHTTP(rw, req)
		return
	}

	wrappedWriter := &responseWriter{
		lastModified:      p.lastModified,
		ResponseWriter:    rw,
		backendStatusCode: http.StatusOK,
		statusCode:        http.StatusOK,
	}
	p.next.ServeHTTP(wrappedWriter, req)

	if wrappedWriter.backendStatusCode == http.StatusNotModified {
		return
	}

	var body []string

	if !p.overwrite && wrappedWriter.backendStatusCode != http.StatusNotFound && wrappedWriter.buffer.String() != "" {
		body = append(body, wrappedWriter.buffer.String()) // Append instead of overwrite.
	}

	if p.enableComment {
		body = append(body, "# The following content was added on the fly by the Security.txt Traefik plugin (See: https://plugins.traefik.io/plugins/6ad1da5af9854753ad5e9d7e/security-txt)") // TODO: Add URL to plugin
	}

	// Add Contact field(s)
	for _, v := range p.contact {
		body = append(body, "Contact: "+v)
	}

	// Add Expires field
	body = append(body, "Expires: "+p.expires)

	// Add optional Policy field
	if p.policy != nil {
		body = append(body, "Policy: "+*p.policy)
	}

	// Add optional Encryption field
	if p.encryption != nil {
		body = append(body, "Encryption: "+*p.encryption)
	}

	// Add optional Hiring field
	if p.hiring != nil {
		body = append(body, "Hiring: "+*p.hiring)
	}

	// Add optional Acknowledgments field
	if p.acknowledgments != nil {
		body = append(body, "Acknowledgments: "+*p.acknowledgments)
	}

	// Add optional Canonical field(s)
	for _, v := range p.canonical {
		body = append(body, "Canonical: "+v)
	}

	// Add optional Preferred-Languages field
	if p.preferredLanguages != nil {
		if len(p.preferredLanguages) != 0 {
			body = append(body, "Preferred-Languages: "+strings.Join(p.preferredLanguages, ", "))
		}
	}

	_, err := rw.Write([]byte(strings.Join(body, "\n")))
	rw.Write([]byte("\n")) // RFC 9116: End with a empty line
	if err != nil {
		log.Printf("unable to write body: %v", err)
	}
}

func (r *responseWriter) WriteHeader(statusCode int) {
	if !r.lastModified {
		r.ResponseWriter.Header().Del("Last-Modified")
	}

	r.wroteHeader = true
	r.backendStatusCode = statusCode
	if statusCode != http.StatusNotFound {
		r.statusCode = statusCode
	} else {
		r.statusCode = http.StatusOK
	}

	r.ResponseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Delegates the Content-Length Header creation to the final body write.
	r.ResponseWriter.Header().Del("Content-Length")

	r.ResponseWriter.WriteHeader(r.statusCode)
}

func (r *responseWriter) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	return r.buffer.Write(p)
}

func (r *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("%T is not a http.Hijacker", r.ResponseWriter)
	}

	return hijacker.Hijack()
}

func (r *responseWriter) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
