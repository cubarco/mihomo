package outbound

import (
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/component/ca"
)

func tuicMemoryOption(token string) TuicOption {
	return TuicOption{
		Name: "fixture", Server: "127.0.0.1", Port: 443, SNI: "proxy.test", Token: token,
		UUID: "9f3fe162-0d26-475b-9f8c-7f121923206a", Password: "fixture",
	}
}

func BenchmarkTuicConstruction(b *testing.B) {
	ca.GetCertPool()
	for _, version := range []string{"v4", "v5"} {
		b.Run(version, func(b *testing.B) {
			token := ""
			if version == "v4" {
				token = "fixture-token"
			}
			option := tuicMemoryOption(token)
			b.ReportAllocs()
			for b.Loop() {
				node, err := NewTuic(option)
				if err != nil {
					b.Fatal(err)
				}
				_ = node.Close()
			}
		})
	}
}

func TestTuicRetainedHeap(t *testing.T) {
	ca.GetCertPool()
	const count = 4096
	for _, version := range []string{"v4", "v5"} {
		t.Run(version, func(t *testing.T) {
			token := ""
			if version == "v4" {
				token = "fixture-token"
			}
			nodes := make([]*Tuic, count)
			t.Cleanup(func() {
				for _, node := range nodes {
					if node != nil {
						_ = node.Close()
					}
				}
			})
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for i := range nodes {
				var err error
				nodes[i], err = NewTuic(tuicMemoryOption(token))
				if err != nil {
					t.Fatal(err)
				}
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			t.Logf("%d unused nodes: retained heap=%d bytes, objects=%d", count,
				int64(after.HeapAlloc)-int64(before.HeapAlloc), int64(after.HeapObjects)-int64(before.HeapObjects))
			runtime.KeepAlive(nodes)
		})
	}
}
