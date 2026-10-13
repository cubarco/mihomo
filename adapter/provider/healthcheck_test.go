package provider

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type countingHealthCheckProxy struct {
	C.Proxy
	calls atomic.Int32
}

type scheduledHealthProxy struct {
	C.Proxy
	name   string
	failed bool
	probe  func(context.Context)
}

func (p *scheduledHealthProxy) Name() string                      { return p.name }
func (p *scheduledHealthProxy) AliveForTestUrl(string) bool       { return !p.failed }
func (p *scheduledHealthProxy) LastDelayForTestUrl(string) uint16 { return 1 }
func (p *scheduledHealthProxy) URLTest(ctx context.Context, _ string, _ utils.IntRanges[uint16]) (uint16, error) {
	p.probe(ctx)
	return 1, ctx.Err()
}

func isolateHealthSchedule(t *testing.T) {
	previous := backgroundHealthChecks
	previousSuspended := healthCheckSuspended.Load()
	previousPriority := healthCheckPriority.Load()
	backgroundHealthChecks = newHealthCheckSchedule()
	healthCheckSuspended.Store(false)
	healthCheckPriority.Store(nil)
	t.Cleanup(func() {
		backgroundHealthChecks.cancel()
		backgroundHealthChecks = previous
		healthCheckSuspended.Store(previousSuspended)
		healthCheckPriority.Store(previousPriority)
	})
}

func TestScheduledChecksBoundAllProvidersWithoutTimingOutQueuedProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		isolateHealthSchedule(t)
		var active, maximum atomic.Int32
		blocking := &scheduledHealthProxy{name: "blocking", probe: func(ctx context.Context) {
			n := active.Add(1)
			for previous := maximum.Load(); n > previous; previous = maximum.Load() {
				if maximum.CompareAndSwap(previous, n) {
					break
				}
			}
			defer active.Add(-1)
			<-ctx.Done()
		}}
		proxies := make([]C.Proxy, 20)
		for i := range proxies {
			proxies[i] = blocking
		}
		first := NewHealthCheck(proxies, "https://probe.test/", 5000, 0, false, nil)
		defer first.close()
		firstDone := make(chan struct{})
		go func() { first.checkScheduled(); close(firstDone) }()
		synctest.Wait()
		if active.Load() != backgroundHealthCheckLimit {
			t.Fatalf("active probes = %d", active.Load())
		}
		var secondCalls atomic.Int32
		quick := &scheduledHealthProxy{name: "quick", probe: func(ctx context.Context) {
			secondCalls.Add(1)
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) != time.Second {
				t.Error("queueing consumed the probe timeout")
			}
		}}
		second := NewHealthCheck([]C.Proxy{quick}, "https://probe.test/", 1000, 0, false, nil)
		defer second.close()
		secondDone := make(chan struct{})
		go func() { second.checkScheduled(); close(secondDone) }()
		canceled := NewHealthCheck([]C.Proxy{quick}, "https://probe.test/", 1000, 0, false, nil)
		canceledDone := make(chan struct{})
		go func() { canceled.checkScheduled(); close(canceledDone) }()
		synctest.Wait()
		canceled.close()
		<-canceledDone
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if secondCalls.Load() != 0 {
			t.Fatal("queued or canceled provider bypassed the global limit")
		}
		manual := NewHealthCheck([]C.Proxy{quick}, "https://probe.test/", 1000, 0, false, nil)
		manual.check()
		manual.close()
		if secondCalls.Load() != 1 {
			t.Fatal("manual check was blocked behind automatic work")
		}
		first.close()
		<-firstDone
		<-secondDone
		if maximum.Load() != backgroundHealthCheckLimit || active.Load() != 0 || secondCalls.Load() != 2 {
			t.Fatal("probe admission leaked a slot or lost queued work")
		}
	})
}

func TestScheduledChecksCancelOnIdleAndResumeAtFreshInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		isolateHealthSchedule(t)
		var calls, canceled atomic.Int32
		proxy := &scheduledHealthProxy{name: "idle", probe: func(ctx context.Context) {
			calls.Add(1)
			<-ctx.Done()
			canceled.Add(1)
		}}
		hc := NewHealthCheck([]C.Proxy{proxy}, "https://probe.test/", 5000, 10, false, nil)
		defer hc.close()
		done := make(chan struct{})
		go func() { hc.process(); close(done) }()
		synctest.Wait()
		SetHealthCheckState(true, false)
		synctest.Wait()
		if calls.Load() != 1 || canceled.Load() != 1 {
			t.Fatal("idle did not cancel running automatic maintenance")
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("idle timer started another health check")
		}
		manual := &countingHealthCheckProxy{}
		manualHC := NewHealthCheck([]C.Proxy{manual}, "https://probe.test/", 1000, 0, false, nil)
		manualHC.check()
		manualHC.close()
		if manual.calls.Load() != 1 {
			t.Fatal("idle disabled explicit health checks")
		}
		SetHealthCheckState(false, false)
		synctest.Wait()
		time.Sleep(10*time.Second - time.Nanosecond)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("wake fired an overdue timer immediately")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("wake did not restart scheduled checks")
		}
		hc.close()
		<-done
	})
}

func TestScheduledChecksPrioritizeFailedAndSelectedNodes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		isolateHealthSchedule(t)
		SetHealthCheckPriority(func() map[string]struct{} { return map[string]struct{}{"selected": {}} })
		started := make(chan string, 20)
		makeProxy := func(name string, failed bool) C.Proxy {
			return &scheduledHealthProxy{name: name, failed: failed, probe: func(ctx context.Context) { started <- name; <-ctx.Done() }}
		}
		var proxies []C.Proxy
		for range 15 {
			proxies = append(proxies, makeProxy("other", false))
		}
		proxies = append(proxies, makeProxy("selected", false), makeProxy("failed", true))
		hc := NewHealthCheck(proxies, "https://probe.test/", 5000, 0, false, nil)
		defer hc.close()
		done := make(chan struct{})
		go func() { hc.checkScheduled(); close(done) }()
		synctest.Wait()
		seen := make(map[string]bool)
		for range backgroundHealthCheckLimit {
			seen[<-started] = true
		}
		if !seen["failed"] || !seen["selected"] {
			t.Fatal("recovery and selected nodes were queued behind unused nodes")
		}
		hc.close()
		<-done
	})
}

func (p *countingHealthCheckProxy) Name() string {
	return "counting"
}

func (p *countingHealthCheckProxy) URLTest(
	context.Context,
	string,
	utils.IntRanges[uint16],
) (uint16, error) {
	p.calls.Add(1)
	return 1, nil
}

func (p *countingHealthCheckProxy) AliveForTestUrl(string) bool {
	return true
}

func (p *countingHealthCheckProxy) LastDelayForTestUrl(string) uint16 {
	return 1
}

func TestHealthCheckSuspendedBlocksManualChecks(t *testing.T) {
	proxy := &countingHealthCheckProxy{}
	healthCheck := NewHealthCheck(
		[]C.Proxy{proxy},
		"https://example.com/generate_204",
		1000,
		0,
		false,
		nil,
	)
	t.Cleanup(func() {
		SetHealthCheckSuspended(false)
		healthCheck.close()
	})

	SetHealthCheckSuspended(true)
	healthCheck.check()
	if got := proxy.calls.Load(); got != 0 {
		t.Fatalf("suspended health check calls = %d", got)
	}

	SetHealthCheckSuspended(false)
	healthCheck.check()
	if got := proxy.calls.Load(); got != 1 {
		t.Fatalf("active health check calls = %d", got)
	}
}
