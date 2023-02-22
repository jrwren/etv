package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/andybalholm/brotli"
)

type brResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w brResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func compress(fn http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// brotli.HTTPCompressor seems to do the wrong thing when negotiating.
		// wc := brotli.HTTPCompressor(w, r)

		// if w.Header().Get("Content-Type") == "" {
		// 	fmt.Printf("cw: %#v\n", cw)
		// 	fn.ServeHTTP(w, r)
		// 	return
		// }

		if w.Header().Get("Vary") == "" {
			w.Header().Set("Vary", "Accept-Encoding")
		}
		var cw io.WriteCloser
		var nw io.Writer
		// I'm also choosing to do negotatie content wrong here
		//encoding := negotiateContentEncoding(r, []string{"br", "gzip"})
		ae := r.Header.Get("Accept-Encoding")
		es := strings.Split(ae, ",")
		sort.Strings(es)
		encoding := strings.TrimSpace(es[0])
		switch encoding {
		case "br":
			w.Header().Set("Content-Encoding", "br")
			cw = brotli.NewWriter(w)
		case "gzip":
			w.Header().Set("Content-Encoding", "gzip")
			cw = gzip.NewWriter(w)
		}
		nw = cw
		if cw != nil {
			defer cw.Close()
		}
		if cw == nil {
			nw = w
		}
		brw := brResponseWriter{Writer: nw, ResponseWriter: w}
		fn.ServeHTTP(brw, r)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is a test."))
}
