package ws

// MessageType represents the type of WebSocket message
type MessageType string

const (
	// Auth
	TypeAuth        MessageType = "auth"
	TypeAuthSuccess MessageType = "auth_success"
	TypeAuthError   MessageType = "auth_error"

	// Heartbeat
	TypePing MessageType = "ping"
	TypePong MessageType = "pong"

	// Configuration
	TypeConfigUpdate MessageType = "config_update"
	TypeConfigAck    MessageType = "config_ack"

	// Status updates
	TypeStatusUpdate MessageType = "status_update"

	// Errors
	TypeError MessageType = "error"
)

// BaseMessage is the base structure for all messages
type BaseMessage struct {
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp"`
}

// AuthMessage is sent by Gateway to authenticate
type AuthMessage struct {
	BaseMessage
	APIKey     string `json:"apiKey"`
	ClientType string `json:"clientType"` // "gateway"
	PublicKey  string `json:"publicKey,omitempty"`
	PublicIP   string `json:"publicIp,omitempty"`
}

// AuthSuccessMessage is received upon successful authentication
type AuthSuccessMessage struct {
	BaseMessage
	ClientID   string `json:"clientId"`
	ClientType string `json:"clientType"`
}

// AuthErrorMessage is received upon authentication failure
type AuthErrorMessage struct {
	BaseMessage
	Error string `json:"error"`
}

// PingMessage for heartbeat
type PingMessage struct {
	BaseMessage
}

// PongMessage for heartbeat response
type PongMessage struct {
	BaseMessage
}

// StatusUpdateMessage is sent to update Gateway status
type StatusUpdateMessage struct {
	BaseMessage
	Status   string                 `json:"status"` // "online", "offline", "error"
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ConfigUpdateMessage is received from Control with configuration
type ConfigUpdateMessage struct {
	BaseMessage
	Config GatewayConfig `json:"config"`
}

// ConfigAckMessage is sent to acknowledge configuration receipt
type ConfigAckMessage struct {
	BaseMessage
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ErrorMessage for error communication
type ErrorMessage struct {
	BaseMessage
	Error string `json:"error"`
}

// GatewayConfig represents Gateway configuration from Control
type GatewayConfig struct {
	Agents []struct {
		ID                 string   `json:"id"`
		Name               string   `json:"name"`
		WireguardPublicKey string   `json:"wireguardPublicKey"`
		AllowedIPs         []string `json:"allowedIPs"` // List of /32 IPs for WireGuard peer
	} `json:"agents"`
	Tunnels []struct {
		ID        string `json:"id"`
		Domain    string `json:"domain"`
		AgentID   string `json:"agentId"`
		Target    string `json:"target"`
		Enabled   bool   `json:"enabled"`
		Subnet    string `json:"subnet"`    // e.g., "10.1.0.0/24"
		GatewayIP string `json:"gatewayIp"` // e.g., "10.1.0.1"
		AgentIP   string `json:"agentIp"`   // e.g., "10.1.0.100"
	} `json:"tunnels"`
}
