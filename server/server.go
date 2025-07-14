package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/UltraTLS/UltraTLS/protocol" // Assuming this path contains your protocol definitions
	"github.com/UltraTLS/UltraTLS/config"   // Your config package
	"github.com/v2fly/v2ray-core/v5/common/net"
)

// ServerConfig holds the server's operational configuration,
// primarily integrating with the loaded Vyper protocol settings.
type ServerConfig struct {
	// Loaded configuration from config.yaml
	VyperConfig *config.Config
	// Handler for accepted Vyper streams (proxy logic, e.g., to target)
	Handler func(stream protocol.Stream)
}

// StartServer initializes and runs the Vyper server, handling TLS,
// client authentication, and the initial Vyper handshake.
func StartServer(cfg *ServerConfig) error {
	if cfg.VyperConfig == nil {
		return fmt.Errorf("server configuration (VyperConfig) is nil")
	}

	// --- Load TLS Certificate and Key ---
	tlsCert, err := tls.LoadX509KeyPair(cfg.VyperConfig.TLSCertPath, cfg.VyperConfig.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate or key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12, // Recommended minimum version
		// Add other TLS configurations as needed, e.g., CipherSuites, MaxVersion
	}

	// --- Handle Client Certificate Authentication if enabled ---
	if cfg.VyperConfig.TLSClientAuth {
		if cfg.VyperConfig.TLSClientCaCertPath == "" {
			return fmt.Errorf("TLS client authentication is enabled but TLSClientCaCertPath is not set")
		}
		caCertPool := protocol.NewCertPool() // Assuming protocol package has a NewCertPool
		caCert, err := os.ReadFile(cfg.VyperConfig.TLSClientCaCertPath)
		if err != nil {
			return fmt.Errorf("failed to read client CA certificate: %w", err)
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse client CA certificate")
		}
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert // Or tls.VerifyClientCertIfGiven
	}

	// --- Initialize TCP Listener ---
	listenAddr := fmt.Sprintf("%s:%d", cfg.VyperConfig.ListenAddress, cfg.VyperConfig.ListenPort)
	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener on %s: %w", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("Vyper server listening on %s", listenAddr)

	for {
		// --- Accept new TLS Connection ---
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server accept TLS connection error: %v", err)
			// Small delay to prevent tight looping on persistent errors
			time.Sleep(time.Second)
			continue
		}

		go func(serverConn net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("recovered from panic in client handler: %v", r)
				}
				serverConn.Close() // Ensure connection is closed on exit
			}()

			log.Printf("Accepted new connection from %s", serverConn.RemoteAddr())

			// --- Vyper Protocol Handshake: Read Initialization Frame ---
			// We expect the first bytes to be the Vyper Initialization Frame.
			// Define a buffer for the initial read (e.g., max size of initial frame)
			// AuthBlob Length (2) + AuthBlob (e.g., 64) + InitialPaddingRule (1) + Reserved (3) + ClientInfo Length (2) = 72 bytes + ClientInfo length
			// Let's assume a reasonable max for client info, e.g., 256 bytes, so 72 + 256 = 328 bytes for the initial buffer.
			// Or, more robustly, read piece by piece.

			// Temporarily use a buffered reader for byte-by-byte parsing
			// For simplicity here, we'll assume a direct read of structured data.
			// In a real implementation, you'd use bufio.Reader to peek/read exact lengths.

			// Read AuthBlob Length
			var authBlobLen uint16
			if err := protocol.ReadBytes(serverConn, &authBlobLen); err != nil { // Assuming protocol.ReadBytes reads big-endian uint16
				log.Printf("failed to read AuthBlob Length from %s: %v", serverConn.RemoteAddr(), err)
				protocol.SendErrorAndClose(serverConn, "Protocol error: missing AuthBlob Length") // Assuming this helper exists
				return
			}
			if authBlobLen == 0 || authBlobLen > 256 { // Arbitrary max length for sanity check
				log.Printf("invalid AuthBlob Length %d from %s", authBlobLen, serverConn.RemoteAddr())
				protocol.SendErrorAndClose(serverConn, "Protocol error: invalid AuthBlob Length")
				return
			}

			// Read AuthBlob
			authBlob := make([]byte, authBlobLen)
			if _, err := serverConn.Read(authBlob); err != nil {
				log.Printf("failed to read AuthBlob from %s: %v", serverConn.RemoteAddr(), err)
				protocol.SendErrorAndClose(serverConn, "Protocol error: missing AuthBlob")
				return
			}

			// --- Authenticate Client ---
			if string(authBlob) != cfg.VyperConfig.AuthToken { // Simple string comparison for authToken, convert Base64 to byte slice in real app
				log.Printf("Authentication failed for %s: invalid AuthBlob", serverConn.RemoteAddr())
				if cfg.VyperConfig.FallbackAddress != "" {
					// Implement fallback to HTTP or other L7 service
					log.Printf("Falling back %s to %s", serverConn.RemoteAddr(), cfg.VyperConfig.FallbackAddress)
					// This part is complex and typically involves hijacking the TCP stream
					// to proxy to the fallback address. For this example, we'll just log
					// and close if we don't have a full HTTP proxy handler here.
					protocol.ServeFallback(serverConn, cfg.VyperConfig.FallbackAddress) // Assuming this helper exists
				} else {
					protocol.SendErrorAndClose(serverConn, "Authentication failed")
				}
				return
			}
			log.Printf("Authentication successful for %s", serverConn.RemoteAddr())

			// Read InitialPaddingRule, Reserved, ClientInfo Length, ClientInfo
			var initialPaddingRule uint8
			if err := protocol.ReadBytes(serverConn, &initialPaddingRule); err != nil { // Assuming protocol.ReadBytes for uint8
				log.Printf("failed to read InitialPaddingRule from %s: %v", serverConn.RemoteAddr(), err)
				protocol.SendErrorAndClose(serverConn, "Protocol error: missing InitialPaddingRule")
				return
			}

			reservedBytes := make([]byte, 3)
			if _, err := serverConn.Read(reservedBytes); err != nil {
				log.Printf("failed to read Reserved bytes from %s: %v", serverConn.RemoteAddr(), err)
				protocol.SendErrorAndClose(serverConn, "Protocol error: missing Reserved bytes")
				return
			}
			// Server MUST ignore Reserved bytes as per SPEC. No validation needed for content.

			var clientInfoLen uint16
			if err := protocol.ReadBytes(serverConn, &clientInfoLen); err != nil { // Assuming protocol.ReadBytes for uint16
				log.Printf("failed to read ClientInfo Length from %s: %v", serverConn.RemoteAddr(), err)
				protocol.SendErrorAndClose(serverConn, "Protocol error: missing ClientInfo Length")
				return
			}
			if clientInfoLen > 512 { // Sanity check for ClientInfo length
				log.Printf("invalid ClientInfo Length %d from %s", clientInfoLen, serverConn.RemoteAddr())
				protocol.SendErrorAndClose(serverConn, "Protocol error: invalid ClientInfo Length")
				return
			}

			clientInfo := make([]byte, clientInfoLen)
			if clientInfoLen > 0 {
				if _, err := serverConn.Read(clientInfo); err != nil {
					log.Printf("failed to read ClientInfo from %s: %v", serverConn.RemoteAddr(), err)
					protocol.SendErrorAndClose(serverConn, "Protocol error: missing ClientInfo")
					return
				}
			}
			log.Printf("Client %s details: InitialPaddingRule=%d, ClientInfo='%s'",
				serverConn.RemoteAddr(), initialPaddingRule, string(clientInfo))

			// --- Vyper Session Start ---
			// Now, the TLS connection is authenticated and the initial handshake is complete.
			// We establish the Mux session over this connection.
			session := protocol.NewSession(serverConn)
			defer session.Close()

			// --- Continuously Accept Mux Streams ---
			for {
				// AcceptStream will block until a new stream (e.g., REQ_FRAME) arrives,
				// or the underlying connection closes/errors.
				// The Vyper protocol framing (REQ_FRAME, DATA_FRAME, etc.)
				// is handled internally by protocol.NewSession and session.AcceptStream.
				// This assumes `protocol.NewSession` abstracts the Vyper session frame parsing.
				stream, _, err := session.AcceptStream()
				if err != nil {
					// Log specific errors for better diagnostics
					if err == protocol.ErrSessionClosed || err == os.EOF { // Assuming these error types exist
						log.Printf("client %s session closed gracefully.", serverConn.RemoteAddr())
					} else {
						log.Printf("server accept mux stream from %s error: %v", serverConn.RemoteAddr(), err)
					}
					break // Break from inner loop to close the connection
				}

				// Hand the accepted stream to the configured handler for proxying.
				// The handler is responsible for reading/writing Vyper DATA_FRAMEs
				// via the provided 'stream' interface.
				go cfg.Handler(stream)
			}
		}(conn)
	}
}
