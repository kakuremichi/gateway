package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// TunnelRoute represents a tunnel routing configuration
type TunnelRoute struct {
	ID         string
	Domain     string
	AgentIP    string // Legacy Agent virtual IP fallback.
	Enabled    bool
	TLSMode    string
	ForceHTTPS bool
	Backends   []BackendRoute

	mu            sync.Mutex
	currentWeight map[string]int
	failedUntil   map[string]time.Time
}

// BackendRoute represents a selectable origin backend behind one tunnel.
type BackendRoute struct {
	ID          string
	AgentID     string
	AgentIP     string
	Target      string
	Enabled     bool
	Draining    bool
	Weight      int
	Priority    int
	AgentStatus string
}

// ControlCertificate represents a certificate bundle pushed from Control.
type ControlCertificate struct {
	ID             string
	Domain         string
	CertificatePEM string
	PrivateKeyPEM  string
}

// ACMEConfig holds ACME/Let's Encrypt configuration
type ACMEConfig struct {
	Email    string
	Staging  bool
	CacheDir string
	Enabled  bool // Whether to enable ACME/TLS

	// Manual TLS (alternative to ACME)
	TLSCertFile string
	TLSKeyFile  string
}

// RuntimeStatus describes how the Gateway proxy is currently serving traffic.
type RuntimeStatus struct {
	HTTPAddress         string `json:"httpAddress"`
	HTTPSAddress        string `json:"httpsAddress"`
	HTTPListening       bool   `json:"httpListening"`
	HTTPSListening      bool   `json:"httpsListening"`
	TLSMode             string `json:"tlsMode"` // disabled, acme, or manual
	ACMEEnabled         bool   `json:"acmeEnabled"`
	ACMEStaging         bool   `json:"acmeStaging"`
	ACMEEmailConfigured bool   `json:"acmeEmailConfigured"`
	ManualTLSEnabled    bool   `json:"manualTlsEnabled"`
	ControlCertCount    int    `json:"controlCertCount"`
	RouteCount          int    `json:"routeCount"`
}

// HTTPProxy represents the HTTP reverse proxy for Gateway
type HTTPProxy struct {
	mu             sync.RWMutex            // guards routes
	routes         map[string]*TunnelRoute // domain -> route
	httpAddr       string                  // HTTP listen address
	httpsAddr      string                  // HTTPS listen address
	acmeManager    *autocert.Manager       // ACME certificate manager
	acmeConfig     ACMEConfig              // ACME configuration
	httpServer     *http.Server            // HTTP server instance
	httpsServer    *http.Server            // HTTPS server instance
	httpListening  bool                    // true while HTTP listener is active
	httpsListening bool                    // true while HTTPS listener is active
	mainHandler    http.Handler            // shared request handler for dynamic HTTPS startup
	ctx            context.Context         // proxy lifetime context
	controlCerts   map[string]*tls.Certificate
	manualCert     *tls.Certificate
}
