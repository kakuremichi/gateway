package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/yourorg/kakuremichi/gateway/internal/config"
	"github.com/yourorg/kakuremichi/gateway/internal/exitnode"
	"github.com/yourorg/kakuremichi/gateway/internal/proxy"
	"github.com/yourorg/kakuremichi/gateway/internal/wireguard"
	"github.com/yourorg/kakuremichi/gateway/internal/ws"
)

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Starting kakuremichi Gateway")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	slog.Info("Configuration loaded",
		"control_url", cfg.ControlURL,
		"wireguard_port", cfg.WireguardPort,
		"http_port", cfg.HTTPPort,
		"https_port", cfg.HTTPSPort,
	)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privateKey, publicKey, err := loadOrCreateWireguardKeys(cfg.WireguardKeyFile)
	if err != nil {
		log.Fatalf("Failed to obtain WireGuard keys: %v", err)
	}
	cfg.WireguardPrivateKey = privateKey
	slog.Info("WireGuard keys ready", "public_key", publicKey)

	// Initialize WireGuard interface
	wgConfig := &wireguard.InterfaceConfig{
		PrivateKey: cfg.WireguardPrivateKey,
		ListenPort: cfg.WireguardPort,
		Addresses:  []string{}, // Will be populated from agent configs
		Peers:      []wireguard.PeerConfig{},
	}

	wg, err := wireguard.NewInterface(cfg.WireguardInterface, wgConfig)
	if err != nil {
		slog.Warn("Failed to create WireGuard interface (may require privileges)", "error", err)
		// Don't fail, just log warning - WireGuard might not be available on all systems
	} else {
		defer wg.Close()
		slog.Info("WireGuard interface initialized", "public_key", wg.PublicKey())
	}

	// Initialize HTTP proxy with ACME configuration
	httpAddr := fmt.Sprintf(":%d", cfg.HTTPPort)
	httpsAddr := fmt.Sprintf(":%d", cfg.HTTPSPort)

	// Configure ACME (enabled if email is provided and not default)
	acmeEnabled := cfg.ACMEEmail != "" && cfg.ACMEEmail != "admin@example.com"
	acmeConfig := proxy.ACMEConfig{
		Email:    cfg.ACMEEmail,
		Staging:  cfg.ACMEStaging,
		CacheDir: cfg.ACMECacheDir,
		Enabled:  acmeEnabled,
	}

	if acmeEnabled {
		slog.Info("ACME/TLS enabled",
			"email", cfg.ACMEEmail,
			"staging", cfg.ACMEStaging,
			"cache_dir", cfg.ACMECacheDir,
		)
	} else {
		slog.Info("ACME/TLS disabled, HTTP-only mode")
	}

	httpProxy := proxy.NewHTTPProxy(httpAddr, httpsAddr, acmeConfig)

	// Start HTTP proxy in background
	go func() {
		if err := httpProxy.Start(ctx); err != nil {
			slog.Error("HTTP proxy stopped", "error", err)
		}
	}()

	// Initialize Exit Node proxies (will be started when config is received)
	var exitHTTPProxy *exitnode.HTTPProxy
	var exitSOCKS5Proxy *exitnode.SOCKS5Proxy

	// Initialize WebSocket client (Control connection) with public key
	// Note: publicKey is from loadOrCreateWireguardKeys, so it works even if WireGuard interface fails (e.g., on Windows)
	wsClient := ws.NewClient(cfg, publicKey)
	wsClient.SetConfigUpdateCallback(func(config ws.GatewayConfig) {
		slog.Info("Received configuration update",
			"agents_count", len(config.Agents),
			"tunnels_count", len(config.Tunnels),
		)

		// Update WireGuard peers
		// Each agent's AllowedIPs now contains the /32 IPs for all its tunnels
		if wg != nil {
			var peers []wireguard.PeerConfig
			for _, agent := range config.Agents {
				if len(agent.AllowedIPs) == 0 {
					continue // Skip agents with no tunnels
				}
				peer := wireguard.PeerConfig{
					PublicKey:           agent.WireguardPublicKey,
					AllowedIPs:          agent.AllowedIPs,
					PersistentKeepalive: 25,
				}
				peers = append(peers, peer)
			}

			if err := wg.UpdatePeers(peers); err != nil {
				slog.Error("Failed to update WireGuard peers", "error", err)
			} else {
				slog.Info("Updated WireGuard peers", "count", len(peers))
			}
		}

		// Update HTTP proxy routes
		// Each tunnel now has its own AgentIP
		var routes []proxy.TunnelRoute
		for _, tunnel := range config.Tunnels {
			if tunnel.AgentIP == "" {
				slog.Warn("Tunnel has no AgentIP", "tunnel_id", tunnel.ID, "domain", tunnel.Domain)
				continue
			}

			route := proxy.TunnelRoute{
				ID:      tunnel.ID,
				Domain:  tunnel.Domain,
				AgentIP: tunnel.AgentIP,
				Enabled: tunnel.Enabled,
			}
			routes = append(routes, route)
		}

		httpProxy.UpdateRoutes(routes)

		// Ensure WireGuard interface has IP addresses for each tunnel's gateway IP
		if wg != nil {
			ensureGatewayIPs(cfg.WireguardInterface, config.Tunnels)
		}

		// Update Exit Node proxies
		// Collect gateway IPs for tunnels with proxy enabled
		var httpProxyIPs, socksProxyIPs []string
		for _, tunnel := range config.Tunnels {
			if tunnel.GatewayIP == "" {
				continue
			}
			if tunnel.HTTPProxyEnabled {
				httpProxyIPs = append(httpProxyIPs, tunnel.GatewayIP)
			}
			if tunnel.SOCKSProxyEnabled {
				socksProxyIPs = append(socksProxyIPs, tunnel.GatewayIP)
			}
		}

		// Start/update HTTP proxy
		if len(httpProxyIPs) > 0 {
			if exitHTTPProxy == nil {
				exitHTTPProxy = exitnode.NewHTTPProxy(config.ProxyConfig.HTTPProxyPort)
			}
			if err := exitHTTPProxy.UpdateListeners(httpProxyIPs); err != nil {
				slog.Error("Failed to update HTTP proxy listeners", "error", err)
			}
		} else if exitHTTPProxy != nil {
			exitHTTPProxy.Stop()
		}

		// Start/update SOCKS5 proxy
		if len(socksProxyIPs) > 0 {
			if exitSOCKS5Proxy == nil {
				exitSOCKS5Proxy = exitnode.NewSOCKS5Proxy(config.ProxyConfig.SOCKSProxyPort)
			}
			if err := exitSOCKS5Proxy.UpdateListeners(socksProxyIPs); err != nil {
				slog.Error("Failed to update SOCKS5 proxy listeners", "error", err)
			}
		} else if exitSOCKS5Proxy != nil {
			exitSOCKS5Proxy.Stop()
		}
	})

	// Connect to Control server
	if err := wsClient.Connect(); err != nil {
		log.Fatalf("Failed to connect to Control: %v", err)
	}
	defer wsClient.Close()

	slog.Info("Gateway started successfully")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("Shutting down Gateway")
	cancel()

	// Graceful shutdown
	httpProxy.Shutdown()
	if exitHTTPProxy != nil {
		exitHTTPProxy.Stop()
	}
	if exitSOCKS5Proxy != nil {
		exitSOCKS5Proxy.Stop()
	}
	if wg != nil {
		wg.Close()
	}

	fmt.Println("Gateway stopped")
}

// ensureGatewayIPs adds gateway IPs for each tunnel's subnet to the WireGuard interface.
// This lets the kernel select a proper source address when proxying to agent IPs.
func ensureGatewayIPs(iface string, tunnels []struct {
	ID                string `json:"id"`
	Domain            string `json:"domain"`
	AgentID           string `json:"agentId"`
	Target            string `json:"target"`
	Enabled           bool   `json:"enabled"`
	Subnet            string `json:"subnet"`
	GatewayIP         string `json:"gatewayIp"`
	AgentIP           string `json:"agentIp"`
	HTTPProxyEnabled  bool   `json:"httpProxyEnabled"`
	SOCKSProxyEnabled bool   `json:"socksProxyEnabled"`
}) {
	// Bring interface up (ignore errors)
	_ = exec.Command("ip", "link", "set", iface, "up").Run()

	seen := make(map[string]struct{})
	for _, tunnel := range tunnels {
		if tunnel.GatewayIP == "" || tunnel.Subnet == "" {
			continue
		}

		_, ipnet, err := net.ParseCIDR(tunnel.Subnet)
		if err != nil || ipnet == nil {
			continue
		}

		// Use the tunnel's gateway IP with subnet mask
		addr := fmt.Sprintf("%s/%d", tunnel.GatewayIP, maskToPrefix(ipnet.Mask))
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}

		cmd := exec.Command("ip", "address", "add", addr, "dev", iface)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Ignore if already exists
			if !strings.Contains(string(out), "File exists") && !strings.Contains(err.Error(), "File exists") {
				slog.Warn("Failed to add IP to WireGuard interface", "addr", addr, "iface", iface, "error", err, "out", string(out))
			}
		} else {
			slog.Info("Added IP to WireGuard interface", "addr", addr, "iface", iface)
		}

		// Ensure route to tunnel subnet via wg interface
		subnetStr := ipnet.String()
		routeCmd := exec.Command("ip", "route", "add", subnetStr, "dev", iface)
		if out, err := routeCmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "File exists") && !strings.Contains(err.Error(), "File exists") {
				slog.Warn("Failed to add route for tunnel subnet", "subnet", subnetStr, "iface", iface, "error", err, "out", string(out))
			}
		} else {
			slog.Info("Added route for tunnel subnet", "subnet", subnetStr, "iface", iface)
		}
	}
}

// maskToPrefix converts a net.IPMask to CIDR prefix length.
func maskToPrefix(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

// loadOrCreateWireguardKeys： (秘密鍵, 公開鍵) を返す
func loadOrCreateWireguardKeys(wireguardKeyFilePath string) (string, string, error) {
	if data, err := os.ReadFile(wireguardKeyFilePath); err == nil {
		priv := strings.TrimSpace(string(data))
		pub, err := wireguard.DerivePublicKey(priv)
		if err == nil {
			slog.Info("Loaded WireGuard key from file", "path", filepath.Clean(wireguardKeyFilePath))
			return priv, pub, nil
		}
		slog.Warn("Existing key file is invalid, regenerating", "path", filepath.Clean(wireguardKeyFilePath), "error", err)
	} else if !os.IsNotExist(err) {
		slog.Warn("Failed to read WireGuard key file, regenerating", "path", filepath.Clean(wireguardKeyFilePath), "error", err)
	}

	priv, pub, err := wireguard.GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	if writeErr := os.WriteFile(wireguardKeyFilePath, []byte(priv+"\n"), 0600); writeErr != nil {
		slog.Warn("Failed to persist WireGuard key", "path", filepath.Clean(wireguardKeyFilePath), "error", writeErr)
	} else {
		slog.Info("Generated new WireGuard key and saved", "path", filepath.Clean(wireguardKeyFilePath))
	}
	return priv, pub, nil
}
