package log

import (
	"sync"
	"testing"
)

func TestLogLevelDuringConcurrentLogging(t *testing.T) {
	previous := Level()
	t.Cleanup(func() { SetLevel(previous) })

	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for range 1000 {
			SetLevel(INFO)
			SetLevel(WARNING)
			SetLevel(SILENT)
		}
	}()
	for range 1000 {
		if current := Level(); current < INFO || current > SILENT {
			t.Errorf("unexpected log level: %v", current)
		}
		Debugln("connection cleanup")
	}
	writer.Wait()
}
