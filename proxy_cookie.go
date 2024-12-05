// Package traefik_plugin_proxy_cookie a traefik plugin providing the functionality of the nginx proxy_cookie directives tp traefik.
package traefik_plugin_proxy_cookie //nolint

import (
	"context"
	"fmt"
	"net/http"
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

type rewriteBody struct {
	name string
	next http.Handler
}

func New(_ context.Context, next http.Handler, _ *Config, name string) (http.Handler, error) {
	return &rewriteBody{
		name: name,
		next: next,
	}, nil
}

var token = ""
var logout = false

func (r *rewriteBody) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Connection") == "Upgrade" && req.Header.Get("Upgrade") == "websocket" {
		// Add or log custom behavior for WebSocket connections if needed
		rw.Header().Set("X-WebSocket-Allowed", "true")
		r.next.ServeHTTP(rw, req)
	} else {
		if(req.
		if req.Method == "GET" {
			if(strings.Contains(req.URL.Path, "/websocket")) {
				r.next.ServeHTTP(rw, req)
			}
			if req.URL.Query() != nil {
				fmt.Println("Query found")
				fmt.Println(req.URL)
				if req.URL.Query().Has("token") {
					fmt.Println("Token found")
					fmt.Println(req.URL.Query().Get("token"))
					fmt.Println(req.URL.Query().Get("stage_url"))
					token = req.URL.Query().Get("token")
				}
			}
			if req.URL != nil && req.URL.Path != "" && req.URL.Path != "/" {
				if strings.Contains(req.URL.Path, "/web/session/logout") {
					fmt.Println("Found logout Path")
					logout = true
				}
			}

			wrappedWriter := &responseWriter{
				writer: rw,
			}

			r.next.ServeHTTP(wrappedWriter, req)
		}
		if req.Method == "POST" || req.Method == "OPTIONS" {
			r.next.ServeHTTP(rw, req)
		}
	}
}

type responseWriter struct {
	writer http.ResponseWriter
}

func (r *responseWriter) Header() http.Header {
	return r.writer.Header()
}

func (r *responseWriter) Write(bytes []byte) (int, error) {
	return r.writer.Write(bytes)
}

func (r *responseWriter) WriteHeader(statusCode int) {
	if token != "" {
		fmt.Println("Set new cookie")
		fmt.Println("Token found")
		r.writer.Header().Del(setCookieHeader)
		expiration := time.Now().Add(24 * 7 * time.Hour)
		cookie := http.Cookie{Name: "session_id", Value: token, Path: "/", HttpOnly: true, Expires: expiration}
		http.SetCookie(r, &cookie)
		token = ""
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
