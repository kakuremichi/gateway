package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yourorg/kakuremichi/gateway/internal/config"
)

// Client represents a WebSocket client for Gateway
type Client struct {
	cfg       *config.Config
	publicKey string // WireGuard public key
	publicIP  string // Public IP address
	conn      *websocket.Conn
	connMu    sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc

	// Channels
	send chan []byte
	recv chan []byte
	done chan struct{}

	// Callbacks
	onConfigUpdate func(config GatewayConfig)

	// Reconnection
	reconnecting bool
	reconnectMu  sync.Mutex
}

// NewClient creates a new WebSocket client
func NewClient(cfg *config.Config, publicKey string) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		cfg:       cfg,
		publicKey: publicKey,
		ctx:       ctx,
		cancel:    cancel,
		send:      make(chan []byte, 256),
		recv:      make(chan []byte, 256),
		done:      make(chan struct{}),
	}
}

// Connect establishes WebSocket connection to Control server with auto-reconnect
func (c *Client) Connect() error {
	// Fetch public IP before connecting
	if err := c.fetchPublicIP(); err != nil {
		slog.Warn("Failed to fetch public IP", "error", err)
		// Continue anyway - publicIP will be empty
	}

	// Initial connection
	if err := c.connect(); err != nil {
		return err
	}

	// Start reconnection monitor
	go c.reconnectLoop()

	return nil
}

// connect performs the actual connection
func (c *Client) connect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	slog.Info("Connecting to Control server", "url", c.cfg.ControlURL, "publicIP", c.publicIP)

	conn, _, err := websocket.DefaultDialer.Dial(c.cfg.ControlURL, nil)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.conn = conn
	slog.Info("Connected to Control server")

	// Send authentication message
	if err := c.authenticate(); err != nil {
		conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Reset done channel for new connection
	c.done = make(chan struct{})

	// Start message handlers
	go c.readPump()
	go c.writePump()
	go c.handleMessages()
	go c.heartbeat()

	return nil
}

// reconnectLoop monitors connection and reconnects when needed
func (c *Client) reconnectLoop() {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.done:
			// Connection closed, attempt reconnect
			c.reconnectMu.Lock()
			if c.reconnecting {
				c.reconnectMu.Unlock()
				continue
			}
			c.reconnecting = true
			c.reconnectMu.Unlock()

			slog.Info("Connection lost, attempting to reconnect...", "backoff", backoff)

			for {
				select {
				case <-c.ctx.Done():
					return
				case <-time.After(backoff):
					// Try to reconnect
					if err := c.connect(); err != nil {
						slog.Warn("Reconnection failed", "error", err, "next_retry", backoff*2)
						backoff *= 2
						if backoff > maxBackoff {
							backoff = maxBackoff
						}
						continue
					}

					// Success
					slog.Info("Reconnected to Control server")
					backoff = time.Second
					c.reconnectMu.Lock()
					c.reconnecting = false
					c.reconnectMu.Unlock()
					break
				}
				break
			}
		}
	}
}

// fetchPublicIP fetches the public IP from the configured checker
func (c *Client) fetchPublicIP() error {
	checkerURL := c.cfg.PublicIPv4Checker
	if checkerURL == "" {
		checkerURL = "https://sweak.net/ip"
	}

	slog.Info("Fetching public IP", "url", checkerURL)

	// Force IPv4 by using a custom dialer
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	resp, err := client.Get(checkerURL)
	if err != nil {
		return fmt.Errorf("failed to fetch public IP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("public IP checker returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	c.publicIP = strings.TrimSpace(string(body))
	slog.Info("Fetched public IP", "ip", c.publicIP)
	return nil
}

// authenticate sends authentication message
func (c *Client) authenticate() error {
	authMsg := AuthMessage{
		BaseMessage: BaseMessage{
			Type:      TypeAuth,
			Timestamp: time.Now().UnixMilli(),
		},
		APIKey:     c.cfg.APIKey,
		ClientType: "gateway",
		PublicKey:  c.publicKey,
		PublicIP:   c.publicIP,
	}

	data, err := json.Marshal(authMsg)
	if err != nil {
		return err
	}

	// Send auth message directly (writePump not started yet)
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return fmt.Errorf("failed to send auth: %w", err)
	}

	// Wait for auth response (with timeout)
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, message, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}
	c.conn.SetReadDeadline(time.Time{}) // Clear deadline

	var baseMsg BaseMessage
	if err := json.Unmarshal(message, &baseMsg); err != nil {
		return err
	}

	if baseMsg.Type == TypeAuthSuccess {
		slog.Info("Authentication successful")
		return nil
	} else if baseMsg.Type == TypeAuthError {
		var errMsg AuthErrorMessage
		json.Unmarshal(message, &errMsg)
		return fmt.Errorf("auth error: %s", errMsg.Error)
	}

	return fmt.Errorf("unexpected message type: %s", baseMsg.Type)
}

// readPump reads messages from WebSocket
func (c *Client) readPump() {
	defer func() {
		c.signalDisconnect()
	}()

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if !websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Info("WebSocket connection closed")
			} else {
				slog.Error("WebSocket read error", "error", err)
			}
			return
		}

		select {
		case c.recv <- message:
		case <-c.ctx.Done():
			return
		}
	}
}

// writePump writes messages to WebSocket
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.signalDisconnect()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.connMu.Lock()
			err := c.conn.WriteMessage(websocket.TextMessage, message)
			c.connMu.Unlock()

			if err != nil {
				slog.Error("WebSocket write error", "error", err)
				return
			}

		case <-ticker.C:
			// Keep-alive ping
			c.connMu.Lock()
			err := c.conn.WriteMessage(websocket.PingMessage, nil)
			c.connMu.Unlock()

			if err != nil {
				return
			}

		case <-c.ctx.Done():
			return
		}
	}
}

// signalDisconnect signals that the connection has been lost
func (c *Client) signalDisconnect() {
	select {
	case c.done <- struct{}{}:
	default:
	}
}

// handleMessages processes received messages
func (c *Client) handleMessages() {
	slog.Info("Message handler started")
	for {
		select {
		case msg := <-c.recv:
			slog.Debug("Raw message received", "length", len(msg))
			c.handleMessage(msg)

		case <-c.ctx.Done():
			slog.Info("Message handler stopped")
			return
		}
	}
}

// handleMessage processes a single message
func (c *Client) handleMessage(data []byte) {
	var baseMsg BaseMessage
	if err := json.Unmarshal(data, &baseMsg); err != nil {
		preview := string(data)
		if len(preview) > 200 {
			preview = preview[:200]
		}
		slog.Error("Failed to parse message", "error", err, "data", preview)
		return
	}

	slog.Info("Received message from Control", "type", baseMsg.Type)

	switch baseMsg.Type {
	case TypePing:
		c.handlePing()

	case TypeConfigUpdate:
		c.handleConfigUpdate(data)

	case TypeError:
		var errMsg ErrorMessage
		json.Unmarshal(data, &errMsg)
		slog.Error("Received error from Control", "error", errMsg.Error)

	default:
		slog.Warn("Unknown message type", "type", baseMsg.Type)
	}
}

// handlePing responds to ping with pong
func (c *Client) handlePing() {
	pongMsg := PongMessage{
		BaseMessage: BaseMessage{
			Type:      TypePong,
			Timestamp: time.Now().UnixMilli(),
		},
	}

	data, _ := json.Marshal(pongMsg)
	c.send <- data
}

// handleConfigUpdate processes configuration update
func (c *Client) handleConfigUpdate(data []byte) {
	var configMsg ConfigUpdateMessage
	if err := json.Unmarshal(data, &configMsg); err != nil {
		slog.Error("Failed to parse config update", "error", err)
		return
	}

	slog.Info("Received configuration update")

	// Call callback if set
	if c.onConfigUpdate != nil {
		c.onConfigUpdate(configMsg.Config)
	}

	// Send acknowledgment
	ackMsg := ConfigAckMessage{
		BaseMessage: BaseMessage{
			Type:      TypeConfigAck,
			Timestamp: time.Now().UnixMilli(),
		},
		Success: true,
	}

	data, _ = json.Marshal(ackMsg)
	c.send <- data
}

// heartbeat sends periodic status updates
func (c *Client) heartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			statusMsg := StatusUpdateMessage{
				BaseMessage: BaseMessage{
					Type:      TypeStatusUpdate,
					Timestamp: time.Now().UnixMilli(),
				},
				Status: "online",
			}

			data, _ := json.Marshal(statusMsg)
			select {
			case c.send <- data:
			default:
				// Channel full, skip this heartbeat
			}

		case <-c.ctx.Done():
			return
		}
	}
}

// Close closes the WebSocket connection
func (c *Client) Close() {
	c.cancel()
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.connMu.Unlock()
}

// SetConfigUpdateCallback sets the callback for configuration updates
func (c *Client) SetConfigUpdateCallback(callback func(GatewayConfig)) {
	c.onConfigUpdate = callback
}
