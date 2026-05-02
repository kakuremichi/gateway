package proxy

import (
	"sync"
	"testing"
)

// TestHTTPProxy_Routes_ConcurrentReadWrite exercises the RWMutex that
// guards the routes map: concurrent UpdateRoutes + GetRoutes must not
// race. Regression test for feedback.md P1-1.
//
// Use `go test -race` to actually detect violations; without -race this
// test still acts as a smoke test for the contract.
func TestHTTPProxy_Routes_ConcurrentReadWrite(t *testing.T) {
	p := NewHTTPProxy(":0", ":0", ACMEConfig{Enabled: false})
	p.UpdateRoutes([]TunnelRoute{
		{ID: "t1", Domain: "example.test", AgentIP: "10.1.0.2", Enabled: true},
	})

	var wg sync.WaitGroup
	const workers = 32
	const iterations = 500

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				p.UpdateRoutes([]TunnelRoute{
					{ID: "t1", Domain: "example.test", AgentIP: "10.1.0.2", Enabled: true},
					{ID: "t2", Domain: "other.test", AgentIP: "10.2.0.2", Enabled: i%2 == 0},
				})
			}
		}(w)
	}

	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = p.GetRoutes()
			}
		}()
	}

	wg.Wait()
}

func TestHTTPProxy_UpdateRoutes_ReplacesMap(t *testing.T) {
	p := NewHTTPProxy(":0", ":0", ACMEConfig{Enabled: false})

	p.UpdateRoutes([]TunnelRoute{
		{Domain: "a.test", AgentIP: "10.1.0.2", Enabled: true},
		{Domain: "b.test", AgentIP: "10.2.0.2", Enabled: true},
	})
	if got := len(p.GetRoutes()); got != 2 {
		t.Fatalf("expected 2 routes, got %d", got)
	}

	p.UpdateRoutes([]TunnelRoute{
		{Domain: "c.test", AgentIP: "10.3.0.2", Enabled: true},
	})
	routes := p.GetRoutes()
	if _, ok := routes["a.test"]; ok {
		t.Error("old route a.test should have been removed")
	}
	if _, ok := routes["c.test"]; !ok {
		t.Error("new route c.test missing")
	}
}

func TestHTTPProxy_DisabledRoutesSkipped(t *testing.T) {
	p := NewHTTPProxy(":0", ":0", ACMEConfig{Enabled: false})

	p.UpdateRoutes([]TunnelRoute{
		{Domain: "on.test", AgentIP: "10.1.0.2", Enabled: true},
		{Domain: "off.test", AgentIP: "10.2.0.2", Enabled: false},
	})
	routes := p.GetRoutes()
	if _, ok := routes["off.test"]; ok {
		t.Error("disabled route should not be served")
	}
	if _, ok := routes["on.test"]; !ok {
		t.Error("enabled route should be served")
	}
}

func TestHTTPProxy_RuntimeStatusReportsModeAndRoutes(t *testing.T) {
	p := NewHTTPProxy(":8080", ":8443", ACMEConfig{
		Email:   "ops@example.test",
		Enabled: true,
		Staging: true,
	})
	p.UpdateRoutes([]TunnelRoute{
		{Domain: "on.test", AgentIP: "10.1.0.2", Enabled: true},
		{Domain: "off.test", AgentIP: "10.2.0.2", Enabled: false},
	})

	status := p.RuntimeStatus()
	if status.HTTPAddress != ":8080" || status.HTTPSAddress != ":8443" {
		t.Fatalf("unexpected addresses: %#v", status)
	}
	if status.TLSMode != "acme" || !status.ACMEEnabled || !status.ACMEStaging || !status.ACMEEmailConfigured {
		t.Fatalf("unexpected ACME status: %#v", status)
	}
	if status.RouteCount != 1 {
		t.Fatalf("expected 1 active route, got %d", status.RouteCount)
	}
}
