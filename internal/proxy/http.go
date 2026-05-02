package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// NewHTTPProxy creates a new HTTP reverse proxy
func NewHTTPProxy(httpAddr, httpsAddr string, acmeConfig ACMEConfig) *HTTPProxy {
	proxy := &HTTPProxy{
		routes:       make(map[string]*TunnelRoute),
		httpAddr:     httpAddr,
		httpsAddr:    httpsAddr,
		acmeConfig:   acmeConfig,
		controlCerts: make(map[string]*tls.Certificate),
	}

	// Initialize ACME manager if enabled
	if acmeConfig.Enabled {
		proxy.initACMEManager()
	}

	return proxy
}

// initACMEManager initializes the ACME certificate manager
func (p *HTTPProxy) initACMEManager() {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(p.acmeConfig.CacheDir, 0700); err != nil {
		slog.Error("Failed to create ACME cache directory", "error", err, "dir", p.acmeConfig.CacheDir)
		return
	}

	slog.Info("Initializing ACME certificate manager",
		"email", p.acmeConfig.Email,
		"staging", p.acmeConfig.Staging,
		"cache_dir", p.acmeConfig.CacheDir,
	)

	// Create autocert manager
	p.acmeManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  p.acmeConfig.Email,
		Cache:  autocert.DirCache(p.acmeConfig.CacheDir),
		HostPolicy: func(ctx context.Context, host string) error {
			// Only allow certificates for domains that have active routes
			p.mu.RLock()
			route, exists := p.routes[host]
			enabled := exists && route.Enabled
			p.mu.RUnlock()
			if enabled {
				slog.Info("ACME: Allowing certificate for domain", "domain", host)
				return nil
			}
			slog.Warn("ACME: Rejecting certificate request for unknown domain", "domain", host)
			return fmt.Errorf("acme: domain not configured: %s", host)
		},
	}

	// Use staging environment if configured
	if p.acmeConfig.Staging {
		p.acmeManager.Client = &acme.Client{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		}
		slog.Info("Using Let's Encrypt STAGING environment")
	}
}

// UpdateRoutes updates the tunnel routes
func (p *HTTPProxy) UpdateRoutes(routes []TunnelRoute) {
	slog.Info("Updating tunnel routes", "count", len(routes))

	newRoutes := make(map[string]*TunnelRoute)
	for i := range routes {
		route := &routes[i]
		if route.Enabled {
			newRoutes[route.Domain] = route
			slog.Info("Added route",
				"domain", route.Domain,
				"agent_ip", route.AgentIP,
				"tls_mode", route.TLSMode,
			)
		}
	}

	p.mu.Lock()
	p.routes = newRoutes
	p.mu.Unlock()
}

// Start starts the HTTP and HTTPS proxy servers
func (p *HTTPProxy) Start(ctx context.Context) error {
	// Create main handler
	mainHandler := http.HandlerFunc(p.handleRequest)
	p.mu.Lock()
	p.mainHandler = mainHandler
	p.ctx = ctx
	p.mu.Unlock()

	// Start HTTP server
	if err := p.startHTTPServer(ctx, mainHandler); err != nil {
		return err
	}

	// Start HTTPS server if ACME is enabled or manual TLS is configured
	if p.acmeConfig.Enabled && p.acmeManager != nil {
		if err := p.startHTTPSServer(ctx, mainHandler); err != nil {
			return err
		}
	} else if p.acmeConfig.TLSCertFile != "" && p.acmeConfig.TLSKeyFile != "" {
		if err := p.startManualTLSServer(ctx, mainHandler); err != nil {
			return err
		}
	}

	// Wait for context cancellation
	<-ctx.Done()
	slog.Info("Shutting down HTTP/HTTPS proxies")

	// Shutdown servers
	shutdownCtx := context.Background()
	if p.httpServer != nil {
		if err := p.httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}
	}
	if p.httpsServer != nil {
		if err := p.httpsServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTPS server shutdown error", "error", err)
		}
	}

	return nil
}

// RuntimeStatus returns the current HTTP/HTTPS listener and TLS mode state.
func (p *HTTPProxy) RuntimeStatus() RuntimeStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	tlsMode := "disabled"
	manualTLSEnabled := p.acmeConfig.TLSCertFile != "" && p.acmeConfig.TLSKeyFile != ""
	controlCertCount := len(p.controlCerts)
	if controlCertCount > 0 {
		tlsMode = "control"
	} else if p.acmeConfig.Enabled {
		tlsMode = "acme"
	} else if manualTLSEnabled {
		tlsMode = "manual"
	}

	return RuntimeStatus{
		HTTPAddress:         p.httpAddr,
		HTTPSAddress:        p.httpsAddr,
		HTTPListening:       p.httpListening,
		HTTPSListening:      p.httpsListening,
		TLSMode:             tlsMode,
		ACMEEnabled:         p.acmeConfig.Enabled,
		ACMEStaging:         p.acmeConfig.Staging,
		ACMEEmailConfigured: p.acmeConfig.Email != "" && p.acmeConfig.Email != "admin@example.com",
		ManualTLSEnabled:    manualTLSEnabled,
		ControlCertCount:    controlCertCount,
		RouteCount:          len(p.routes),
	}
}

// UpdateCertificates replaces the Control-managed certificate store.
func (p *HTTPProxy) UpdateCertificates(certificates []ControlCertificate) error {
	newCerts := make(map[string]*tls.Certificate)
	for _, bundle := range certificates {
		cert, err := tls.X509KeyPair([]byte(bundle.CertificatePEM), []byte(bundle.PrivateKeyPEM))
		if err != nil {
			return fmt.Errorf("failed to parse certificate for %s: %w", bundle.Domain, err)
		}
		domain := normalizeHost(bundle.Domain)
		newCerts[domain] = &cert
		slog.Info("Loaded Control-managed certificate", "domain", domain, "certificate_id", bundle.ID)
	}

	p.mu.Lock()
	p.controlCerts = newCerts
	needsHTTPS := len(newCerts) > 0 && p.httpsServer == nil && p.mainHandler != nil && p.ctx != nil
	ctx := p.ctx
	handler := p.mainHandler
	p.mu.Unlock()

	if needsHTTPS {
		return p.startDynamicTLSServer(ctx, handler, "control")
	}
	return nil
}

func (p *HTTPProxy) setHTTPListening(listening bool) {
	p.mu.Lock()
	p.httpListening = listening
	p.mu.Unlock()
}

func (p *HTTPProxy) setHTTPSListening(listening bool) {
	p.mu.Lock()
	p.httpsListening = listening
	p.mu.Unlock()
}

// startHTTPServer starts the HTTP server
func (p *HTTPProxy) startHTTPServer(ctx context.Context, mainHandler http.Handler) error {
	slog.Info("Starting HTTP proxy", "addr", p.httpAddr)

	mux := http.NewServeMux()

	// Mount ACME HTTP-01 challenge handler if ACME is enabled
	if p.acmeConfig.Enabled && p.acmeManager != nil {
		// ACME HTTP-01 challenge handler takes precedence
		mux.Handle("/.well-known/acme-challenge/", p.acmeManager.HTTPHandler(nil))
		slog.Info("ACME HTTP-01 challenge handler mounted at /.well-known/acme-challenge/")
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if p.acmeConfig.Enabled && p.acmeManager != nil && filepath.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			p.acmeManager.HTTPHandler(nil).ServeHTTP(w, r)
			return
		}

		host := hostWithoutPort(r.Host)
		if p.shouldRedirectHTTP(host) {
			target := "https://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			slog.Debug("Redirecting HTTP to HTTPS", "from", r.URL.String(), "to", target)
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}

		mainHandler.ServeHTTP(w, r)
	})

	p.httpServer = &http.Server{
		Addr:    p.httpAddr,
		Handler: mux,
	}

	listener, err := net.Listen("tcp", p.httpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on HTTP %s: %w", p.httpAddr, err)
	}
	p.setHTTPListening(true)

	// Start server in goroutine
	go func() {
		defer p.setHTTPListening(false)
		if err := p.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
		}
	}()

	return nil
}

// startHTTPSServer starts the HTTPS server with ACME
func (p *HTTPProxy) startHTTPSServer(ctx context.Context, mainHandler http.Handler) error {
	return p.startDynamicTLSServer(ctx, mainHandler, "acme")
}

// startManualTLSServer starts the HTTPS server with manually provided certificate
func (p *HTTPProxy) startManualTLSServer(ctx context.Context, mainHandler http.Handler) error {
	slog.Info("Starting HTTPS proxy with manual TLS", "addr", p.httpsAddr,
		"cert", p.acmeConfig.TLSCertFile, "key", p.acmeConfig.TLSKeyFile)

	cert, err := tls.LoadX509KeyPair(p.acmeConfig.TLSCertFile, p.acmeConfig.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load manual TLS certificate: %w", err)
	}
	p.mu.Lock()
	p.manualCert = &cert
	p.mu.Unlock()

	if err := p.startDynamicTLSServer(ctx, mainHandler, "manual"); err != nil {
		return err
	}

	slog.Info("HTTPS server started with manual TLS certificate")
	return nil
}

func (p *HTTPProxy) startDynamicTLSServer(ctx context.Context, mainHandler http.Handler, mode string) error {
	p.mu.Lock()
	if p.httpsServer != nil {
		p.mu.Unlock()
		return nil
	}
	p.httpsServer = &http.Server{
		Addr:    p.httpsAddr,
		Handler: mainHandler,
		TLSConfig: &tls.Config{
			GetCertificate: p.getCertificate,
			MinVersion:     tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		},
	}
	server := p.httpsServer
	p.mu.Unlock()

	slog.Info("Starting HTTPS proxy", "addr", p.httpsAddr, "mode", mode)
	listener, err := tls.Listen("tcp", p.httpsAddr, server.TLSConfig)
	if err != nil {
		p.mu.Lock()
		if p.httpsServer == server {
			p.httpsServer = nil
		}
		p.mu.Unlock()
		return fmt.Errorf("failed to listen on HTTPS %s: %w", p.httpsAddr, err)
	}
	p.setHTTPSListening(true)

	go func() {
		defer p.setHTTPSListening(false)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTPS server error", "error", err)
		}
	}()

	slog.Info("HTTPS server started", "mode", mode)
	return nil
}

func (p *HTTPProxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := normalizeHost(hello.ServerName)
	if host != "" {
		p.mu.RLock()
		if cert := p.controlCerts[host]; cert != nil {
			p.mu.RUnlock()
			return cert, nil
		}
		if cert := p.matchWildcardControlCertLocked(host); cert != nil {
			p.mu.RUnlock()
			return cert, nil
		}
		manualCert := p.manualCert
		p.mu.RUnlock()

		if p.acmeConfig.Enabled && p.acmeManager != nil {
			return p.acmeManager.GetCertificate(hello)
		}
		if manualCert != nil {
			return manualCert, nil
		}
		return nil, fmt.Errorf("no certificate configured for %s", host)
	}

	p.mu.RLock()
	manualCert := p.manualCert
	p.mu.RUnlock()
	if manualCert != nil {
		return manualCert, nil
	}
	if p.acmeConfig.Enabled && p.acmeManager != nil {
		return p.acmeManager.GetCertificate(hello)
	}
	return nil, fmt.Errorf("no server name in TLS client hello")
}

func (p *HTTPProxy) shouldRedirectHTTP(host string) bool {
	host = normalizeHost(host)
	p.mu.RLock()
	defer p.mu.RUnlock()
	route := p.routes[host]
	if route == nil || !route.Enabled || !route.ForceHTTPS {
		return false
	}
	if p.acmeConfig.Enabled && route.TLSMode != "disabled" {
		return true
	}
	return p.hasControlCertLocked(host)
}

func (p *HTTPProxy) hasControlCertLocked(host string) bool {
	if p.controlCerts[host] != nil {
		return true
	}
	return p.matchWildcardControlCertLocked(host) != nil
}

func (p *HTTPProxy) matchWildcardControlCertLocked(host string) *tls.Certificate {
	for domain, cert := range p.controlCerts {
		if !strings.HasPrefix(domain, "*.") {
			continue
		}
		suffix := domain[1:]
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		left := strings.TrimSuffix(host, suffix)
		if left != "" && !strings.Contains(left, ".") {
			return cert
		}
	}
	return nil
}

func hostWithoutPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(hostWithoutPort(host)), ".")
}

// handleRequest handles incoming HTTP/HTTPS requests
func (p *HTTPProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	slog.Debug("Received request", "host", host, "path", r.URL.Path, "method", r.Method, "proto", r.Proto)

	// Find route for this domain
	p.mu.RLock()
	route, exists := p.routes[host]
	p.mu.RUnlock()
	if !exists {
		slog.Warn("No route found for domain", "domain", host)
		http.Error(w, "No tunnel configured for this domain", http.StatusNotFound)
		return
	}

	if !route.Enabled {
		slog.Warn("Route is disabled", "domain", host)
		http.Error(w, "Tunnel is disabled", http.StatusServiceUnavailable)
		return
	}

	// Build target URL (Agent's virtual IP)
	targetURL, err := url.Parse("http://" + route.AgentIP + ":80")
	if err != nil {
		slog.Error("Invalid agent IP", "agent_ip", route.AgentIP, "error", err)
		http.Error(w, "Invalid target configuration", http.StatusInternalServerError)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Customize the director
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = host // Preserve original Host header

		// Set X-Forwarded headers
		req.Header.Set("X-Forwarded-Host", host)

		// Determine protocol
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}
		req.Header.Set("X-Forwarded-Proto", proto)

		// Set X-Real-IP
		if realIP := r.Header.Get("X-Real-IP"); realIP == "" {
			// Extract IP from RemoteAddr
			if remoteIP := r.RemoteAddr; remoteIP != "" {
				req.Header.Set("X-Real-IP", remoteIP)
			}
		}
	}

	// Error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("Proxy error", "error", err, "agent_ip", route.AgentIP)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	slog.Info("Proxying request",
		"domain", host,
		"agent_ip", route.AgentIP,
		"path", r.URL.Path,
		"tls", r.TLS != nil,
	)

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

// Shutdown gracefully shuts down the proxy
func (p *HTTPProxy) Shutdown() error {
	slog.Info("HTTP proxy shutdown initiated")

	// Servers are shut down in the Start() method's context cancellation handler

	return nil
}

// GetRoutes returns current routes (for testing/debugging)
func (p *HTTPProxy) GetRoutes() map[string]*TunnelRoute {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make(map[string]*TunnelRoute, len(p.routes))
	for k, v := range p.routes {
		result[k] = v
	}
	return result
}
