package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// NoDateForSystemDHandler is a logging handler which writes most fields of
// a vhost combined logger without the date, because systemd logs a date.
// Normal vhost-combined apache format:
//   %v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i
// Ours:
//   %v:%p %h %u \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i
func NoDateForSystemDHandler(out io.Writer, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: add a nolog match parameter.
		if r.RequestURI == "/metrics" {
			h.ServeHTTP(w, r)
			return
		}
		host := r.Host
		user := "-"
		auth := r.Header.Get("Authorization")

		if strings.HasPrefix(auth, "Basic ") {
			up, err := base64.RawStdEncoding.DecodeString(auth[6:])
			if err == nil {
				ups := strings.SplitN(string(up), ":", 2)
				if len(ups) == 2 {
					user = ups[0]
				}
			}

		}
		if r.URL.User != nil {
			if un := r.URL.User.Username(); un != "" {
				user = un
			}
		}
		t := time.Now() // Not to log the time, but to compute time of request.
		ww := &wrappedResponseWriter{ResponseWriter: w, code: 200}
		referer := r.Header.Get("Referer")
		ua := r.Header.Get("User-Agent")
		h.ServeHTTP(ww, r)
		rt := time.Since(t)

		fmt.Fprintf(out, "%s %s %s \"%s %s %s\" %d %d %q %q %s\n",
			host, r.RemoteAddr, user, r.Method, r.RequestURI,
			r.Proto, ww.code, ww.size, referer, ua, rt)
	})
}

type wrappedResponseWriter struct {
	http.ResponseWriter     // the underlying ResponseWriter.
	code                int // http code returned.
	size                int // size of http response.
}

func (w *wrappedResponseWriter) Write(b []byte) (int, error) {
	s, err := w.ResponseWriter.Write(b)
	w.size += s
	return s, err
}

func (w *wrappedResponseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
