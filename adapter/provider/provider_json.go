package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	"github.com/metacubex/mihomo/adapter"
	P "github.com/metacubex/mihomo/constant/provider"
)

// WriteJSON streams a provider snapshot without buffering its complete node list.
// Callers should buffer small writes and discard any partial response on error.
func WriteJSON(ctx context.Context, w io.Writer, provider P.ProxyProvider) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var head providerForApi
	switch p := provider.(type) {
	case *ProxySetProvider:
		if p != nil {
			head = p.apiSnapshot()
			break
		}
		return writeJSONValue(w, provider)
	case *InlineProvider:
		if p != nil {
			head = p.apiSnapshot()
			break
		}
		return writeJSONValue(w, provider)
	case *CompatibleProvider:
		if p != nil {
			head = p.apiSnapshot()
			break
		}
		return writeJSONValue(w, provider)
	default:
		return writeJSONValue(w, provider)
	}
	proxies := head.Proxies
	head.Proxies = nil
	encoded, err := json.Marshal(head)
	if err != nil {
		return &json.MarshalerError{Type: reflect.TypeOf(provider), Err: err}
	}
	if proxies == nil {
		return writeJSONBytes(w, encoded)
	}
	const marker = `"proxies":null`
	at := bytes.Index(encoded, []byte(marker))
	if at < 0 {
		return errors.New("provider JSON without proxies")
	}
	at += len(`"proxies":`)
	if err := writeJSONBytes(w, encoded[:at]); err != nil {
		return err
	}
	if err := writeJSONText(w, "["); err != nil {
		return err
	}
	for i, proxy := range proxies {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			if err := writeJSONText(w, ","); err != nil {
				return err
			}
		}
		if err := adapter.WriteProxyJSON(w, proxy); err != nil {
			var marshalError *json.MarshalerError
			if errors.As(err, &marshalError) {
				return &json.MarshalerError{Type: reflect.TypeOf(provider), Err: err}
			}
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeJSONText(w, "]"); err != nil {
		return err
	}
	return writeJSONBytes(w, encoded[at+len("null"):])
}

func writeJSONValue(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeJSONBytes(w, data)
}

func writeJSONBytes(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

func writeJSONText(w io.Writer, text string) error {
	n, err := io.WriteString(w, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	return err
}
