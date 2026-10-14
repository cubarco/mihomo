package route

import (
	"bufio"
	"encoding/json"
	"io"
	"slices"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

const proxyJSONBufferSize = 4 << 10

type jsonResponseWriter struct {
	http.ResponseWriter
	request *http.Request
	started bool
}

func (w *jsonResponseWriter) Write(data []byte) (int, error) {
	if err := w.request.Context().Err(); err != nil {
		return 0, err
	}
	if !w.started {
		w.started = true
		w.Header().Set("Content-Type", "application/json")
		if status, ok := w.request.Context().Value(render.StatusCtxKey).(int); ok {
			w.WriteHeader(status)
		}
	}
	n, err := w.ResponseWriter.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

type jsonStream struct {
	writer  *bufio.Writer
	request *http.Request
	err     error
}

func (s *jsonStream) ok() bool {
	if s.err == nil {
		s.err = s.request.Context().Err()
	}
	return s.err == nil
}

func (s *jsonStream) text(value string) {
	if s.ok() {
		_, s.err = s.writer.WriteString(value)
	}
}

func (s *jsonStream) value(value any) {
	if !s.ok() {
		return
	}
	var data []byte
	data, s.err = json.Marshal(value)
	if s.ok() {
		_, s.err = s.writer.Write(data)
	}
}

func (s *jsonStream) provider(value P.ProxyProvider) {
	if s.ok() {
		s.err = provider.WriteJSON(s.request.Context(), s.writer, value)
	}
}

func (s *jsonStream) proxy(value C.Proxy) {
	if s.ok() {
		s.err = adapter.WriteProxyJSON(s.writer, value)
	}
}

func streamJSON(w http.ResponseWriter, r *http.Request, write func(*jsonStream)) {
	if r.Context().Err() != nil {
		return
	}
	response := &jsonResponseWriter{ResponseWriter: w, request: r}
	s := &jsonStream{writer: bufio.NewWriterSize(response, proxyJSONBufferSize), request: r}
	write(s)
	s.text("\n")
	if s.ok() {
		s.err = s.writer.Flush()
	}
	if s.err != nil {
		// Once headers are sent, abort the transfer instead of completing truncated JSON.
		if response.started {
			panic(http.ErrAbortHandler)
		}
		if r.Context().Err() == nil {
			http.Error(w, s.err.Error(), http.StatusInternalServerError)
		}
	}
}

func streamJSONMap[V any](s *jsonStream, values map[string]V, write func(V)) {
	if !s.ok() {
		return
	}
	if values == nil {
		s.text("null")
		return
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	s.text("{")
	for i, name := range names {
		if !s.ok() {
			return
		}
		if i > 0 {
			s.text(",")
		}
		s.value(name)
		s.text(":")
		if s.ok() {
			write(values[name])
		}
	}
	s.text("}")
}

func writeProxiesJSON(w http.ResponseWriter, r *http.Request, proxies map[string]C.Proxy) {
	streamJSON(w, r, func(s *jsonStream) {
		s.text(`{"proxies":`)
		streamJSONMap(s, proxies, s.proxy)
		s.text("}")
	})
}

func writeProvidersJSON(w http.ResponseWriter, r *http.Request, providers map[string]P.ProxyProvider) {
	streamJSON(w, r, func(s *jsonStream) {
		s.text(`{"providers":`)
		streamJSONMap(s, providers, s.provider)
		s.text("}")
	})
}

func writeProviderJSON(w http.ResponseWriter, r *http.Request, provider P.ProxyProvider) {
	streamJSON(w, r, func(s *jsonStream) { s.provider(provider) })
}
