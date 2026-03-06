package exitnode

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

// SOCKS5 constants
const (
	socks5Version = 0x05
	noAuth        = 0x00

	// Command types
	cmdConnect = 0x01
	// cmdBind      = 0x02 // Not implemented
	// cmdUDPAssoc  = 0x03 // Not implemented

	// Address types
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04

	// Reply codes
	repSuccess             = 0x00
	repGeneralFailure      = 0x01
	repConnectionNotAllowed = 0x02
	repNetworkUnreachable  = 0x03
	repHostUnreachable     = 0x04
	repConnectionRefused   = 0x05
	repTTLExpired          = 0x06
	repCmdNotSupported     = 0x07
	repAddrTypeNotSupported = 0x08
)

// SOCKS5Proxy is a SOCKS5 proxy server for Exit Node functionality.
type SOCKS5Proxy struct {
	port      int
	listeners []net.Listener
	mu        sync.Mutex
	running   bool
}

// NewSOCKS5Proxy creates a new SOCKS5 proxy server
func NewSOCKS5Proxy(port int) *SOCKS5Proxy {
	return &SOCKS5Proxy{
		port: port,
	}
}

// Start starts SOCKS5 proxy listeners on the given gateway IPs
func (p *SOCKS5Proxy) Start(gatewayIPs []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	for _, ip := range gatewayIPs {
		addr := fmt.Sprintf("%s:%d", ip, p.port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			slog.Warn("Failed to start SOCKS5 proxy listener", "addr", addr, "error", err)
			continue
		}

		p.listeners = append(p.listeners, listener)
		slog.Info("SOCKS5 proxy listening", "addr", addr)

		go p.serve(listener)
	}

	p.running = true
	return nil
}

// UpdateListeners updates the listener addresses based on new gateway IPs
func (p *SOCKS5Proxy) UpdateListeners(gatewayIPs []string) error {
	p.Stop()
	return p.Start(gatewayIPs)
}

// serve accepts connections and handles them
func (p *SOCKS5Proxy) serve(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a single SOCKS5 connection
func (p *SOCKS5Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// SOCKS5 handshake
	if err := p.handleHandshake(clientConn); err != nil {
		slog.Debug("SOCKS5 handshake failed", "error", err)
		return
	}

	// Handle request
	if err := p.handleRequest(clientConn); err != nil {
		slog.Debug("SOCKS5 request failed", "error", err)
		return
	}
}

// handleHandshake performs SOCKS5 authentication handshake
func (p *SOCKS5Proxy) handleHandshake(conn net.Conn) error {
	// Read version and number of methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	// Check for no-auth method
	hasNoAuth := false
	for _, m := range methods {
		if m == noAuth {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		conn.Write([]byte{socks5Version, 0xFF}) // No acceptable methods
		return fmt.Errorf("no acceptable auth method")
	}

	// Send no-auth response
	conn.Write([]byte{socks5Version, noAuth})
	return nil
}

// handleRequest handles the SOCKS5 request
func (p *SOCKS5Proxy) handleRequest(conn net.Conn) error {
	// Read request header: VER CMD RSV ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read request header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	cmd := header[1]
	addrType := header[3]

	// Parse destination address
	destAddr, err := p.parseAddress(conn, addrType)
	if err != nil {
		p.sendReply(conn, repAddrTypeNotSupported)
		return err
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return fmt.Errorf("failed to read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)

	target := fmt.Sprintf("%s:%d", destAddr, port)
	slog.Debug("SOCKS5 request", "cmd", cmd, "target", target)

	switch cmd {
	case cmdConnect:
		return p.handleConnect(conn, target)
	default:
		p.sendReply(conn, repCmdNotSupported)
		return fmt.Errorf("unsupported command: %d", cmd)
	}
}

// parseAddress parses the destination address based on address type
func (p *SOCKS5Proxy) parseAddress(conn net.Conn, addrType byte) (string, error) {
	switch addrType {
	case addrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil

	case addrTypeDomain:
		// Read domain length
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return "", err
		}
		domainLen := int(lenByte[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		return string(domain), nil

	case addrTypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil

	default:
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}
}

// handleConnect handles SOCKS5 CONNECT command
func (p *SOCKS5Proxy) handleConnect(clientConn net.Conn, target string) error {
	// Connect to destination
	destConn, err := net.Dial("tcp", target)
	if err != nil {
		slog.Debug("Failed to connect to destination", "target", target, "error", err)
		p.sendReply(clientConn, repHostUnreachable)
		return err
	}
	defer destConn.Close()

	// Send success reply
	p.sendReply(clientConn, repSuccess)

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
	return nil
}

// sendReply sends a SOCKS5 reply
func (p *SOCKS5Proxy) sendReply(conn net.Conn, rep byte) {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	// Using 0.0.0.0:0 as bound address
	reply := []byte{
		socks5Version,
		rep,
		0x00, // RSV
		addrTypeIPv4,
		0, 0, 0, 0, // BND.ADDR
		0, 0, // BND.PORT
	}
	conn.Write(reply)
}

// Stop stops all SOCKS5 proxy listeners
func (p *SOCKS5Proxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, listener := range p.listeners {
		listener.Close()
	}
	p.listeners = nil
	p.running = false
}
