package server

import (
	"github.com/UltraTLS/UltraTLS/protocol"
	"log"
	"time"
	"github.com/v2fly/v2ray-core/v5/common/net"
)

// ServerConfig
type ServerConfig struct {
	ListenAddr string
	Handler    func(stream protocol.Stream)
}

func StartServer(cfg *ServerConfig) error {
	inbound := protocol.NewTCPInbound(cfg.ListenAddr)
	if err := inbound.Listen(); err != nil {
		return err
	}
	defer inbound.Close()
	for {
		conn, err := inbound.Accept()
		if err != nil {
			log.Printf("server accept error: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go func(serverConn net.Conn) {
			// 建立mux session
			session := protocol.NewSession(serverConn)
			defer session.Close()
			// 持续接受子流
			for {
				stream, _, err := session.AcceptStream()
				if err != nil {
					log.Printf("server accept mux stream error: %v", err)
					break
				}
				go cfg.Handler(stream)
			}
		}(conn)
	}
}
