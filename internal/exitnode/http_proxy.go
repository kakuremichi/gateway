package exitnode

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
)

// HTTPProxy is an HTTP CONNECT proxy server for Exit Node functionality.
// It listens on Gateway's WireGuard IPs and forwards traffic to the internet.
type HTTPProxy struct {
	port      int
	listeners []net.Listener
	mu        sync.Mutex
	running   bool
}

// NewHTTPProxy creates a new HTTP proxy server
func NewHTTPProxy(port int) *HTTPProxy {
	return &HTTPProxy{
		port: port,
	}
}

// Start starts HTTP proxy listeners on the given gateway IPs
func (p *HTTPProxy) Start(gatewayIPs []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	for _, ip := range gatewayIPs {
		addr := fmt.Sprintf("%s:%d", ip, p.port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			slog.Warn("Failed to start HTTP proxy listener", "addr", addr, "error", err)
			continue
		}

		p.listeners = append(p.listeners, listener)
		slog.Info("HTTP proxy listening", "addr", addr)

		go p.serve(listener)
	}

	p.running = true
	return nil
}

// UpdateListeners updates the listener addresses based on new gateway IPs
func (p *HTTPProxy) UpdateListeners(gatewayIPs []string) error {
	p.Stop()
	return p.Start(gatewayIPs)
}

// serve accepts connections and handles them
func (p *HTTPProxy) serve(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if listener was closed
			select {
			default:
				slog.Debug("HTTP proxy accept error", "error", err)
			}
			return
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a single proxy connection
func (p *HTTPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		slog.Debug("Failed to read HTTP request", "error", err)
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(clientConn, req)
	} else {
		p.handleHTTP(clientConn, req)
	}
}

// handleConnect handles HTTPS tunneling via CONNECT method
func (p *HTTPProxy) handleConnect(clientConn net.Conn, req *http.Request) {
	slog.Debug("HTTP CONNECT request", "host", req.Host)

	// Connect to destination
	destConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		slog.Debug("Failed to connect to destination", "host", req.Host, "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(destConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, destConn)
	}()

	wg.Wait()
}

// handleHTTP handles plain HTTP requests (non-CONNECT)
func (p *HTTPProxy) handleHTTP(clientConn net.Conn, req *http.Request) {
	slog.Debug("HTTP request", "method", req.Method, "url", req.URL.String())

	// Determine target address
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// Add port if missing
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}

	// Connect to destination
	destConn, err := net.Dial("tcp", host)
	if err != nil {
		slog.Debug("Failed to connect to destination", "host", host, "error", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	// Forward the request
	req.Write(destConn)

	// Copy response back
	io.Copy(clientConn, destConn)
}

// Stop stops all HTTP proxy listeners
func (p *HTTPProxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, listener := range p.listeners {
		listener.Close()
	}
	p.listeners = nil
	p.running = false
}
