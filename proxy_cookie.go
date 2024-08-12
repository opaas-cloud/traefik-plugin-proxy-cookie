// Package traefik_plugin_proxy_cookie a traefik plugin providing the functionality of the nginx proxy_cookie directives tp traefik.
package traefik_plugin_proxy_cookie //nolint

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const setCookieHeader string = "Set-Cookie"

type Rewrite struct {
	Name        string `json:"name,omitempty" toml:"name,omitempty" yaml:"name,omitempty"`
	Regex       string `json:"regex,omitempty" toml:"regex,omitempty" yaml:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty" toml:"replacement,omitempty" yaml:"replacement,omitempty"`
}

// Config holds the plugin configuration.
type Config struct {
	Rewrites []Rewrite `json:"rewrites,omitempty" toml:"rewrites,omitempty" yaml:"rewrites,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type rewrite struct {
	name        string
	regex       *regexp.Regexp
	replacement string
}

type rewriteBody struct {
	name     string
	next     http.Handler
	rewrites []rewrite
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	rewrites := make([]rewrite, len(config.Rewrites))

	for i, rewriteConfig := range config.Rewrites {
		regex, err := regexp.Compile(rewriteConfig.Regex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regex %q: %w", rewriteConfig.Regex, err)
		}

		rewrites[i] = rewrite{
			name:        rewriteConfig.Name,
			regex:       regex,
			replacement: rewriteConfig.Replacement,
		}
	}

	return &rewriteBody{
		name:     name,
		next:     next,
		rewrites: rewrites,
	}, nil
}

var token = ""
var stageUrl = ""
var logout = false

func (r *rewriteBody) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if strings.Contains(req.URL.Path, "/websocket") {
		hijacker, ok := rw.(http.Hijacker)
		if !ok {
			http.Error(rw, "Hijacking not supported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			log.Println("Hijack failed:", err)
			return
		}
		defer conn.Close()
		return
	}
	if req.Method != "GET" {
		wrappedWriter := &responseWriter{
			writer:   rw,
			rewrites: r.rewrites,
		}
		r.next.ServeHTTP(wrappedWriter, req)
		return
	}
	if req.URL.Query() != nil {
		fmt.Println("Query found")
		fmt.Println(req.URL)
		if req.URL.Query().Has("token") {
			fmt.Println("Token found")
			fmt.Println(req.URL.Query().Get("token"))
			fmt.Println(req.URL.Query().Get("stage_url"))
			token = req.URL.Query().Get("token")
			stageUrl = req.URL.Query().Get("stage_url")
		}
	}
	if req.URL != nil && req.URL.Path != "" && req.URL.Path != "/" {
		if strings.Contains(req.URL.Path, "/web/session/logout") {
			fmt.Println("Found logout Path")
			logout = true
		}
	}
	wrappedWriter := &responseWriter{
		writer:   rw,
		rewrites: r.rewrites,
	}
	r.next.ServeHTTP(wrappedWriter, req)
}

type responseWriter struct {
	writer   http.ResponseWriter
	rewrites []rewrite
}

func (r *responseWriter) Header() http.Header {
	return r.writer.Header()
}

func (r *responseWriter) Write(bytes []byte) (int, error) {
	return r.writer.Write(bytes)
}

func (r *responseWriter) WriteHeader(statusCode int) {
	if token != "" && stageUrl != "" {
		fmt.Println("Set new cookie")
		fmt.Println("Token found")
		r.writer.Header().Del(setCookieHeader)
		expiration := time.Now().Add(24 * 7 * time.Hour)
		cookie := http.Cookie{Name: "session_id", Value: token, Path: "/", HttpOnly: true, Expires: expiration}
		http.SetCookie(r, &cookie)
		token = ""
		stageUrl = ""
	}
	if logout {
		fmt.Println("Logout user")
		headers := r.writer.Header()
		req := http.Response{Header: headers}
		cookies := req.Cookies()

		r.writer.Header().Del(setCookieHeader)

		for _, cookie := range cookies {
			if cookie.Name == "session_id" {
				fmt.Println("Found cookie session_id")
				if cookie.MaxAge != -1 {
					fmt.Println("Set cookie age to -1")
					cookie.MaxAge = -1
					http.SetCookie(r, cookie)
				}
			}
		}
		logout = false
	}
	r.writer.WriteHeader(statusCode)
}
