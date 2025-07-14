package client

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/UltraTLS/UltraTLS/config"
	"github.com/UltraTLS/UltraTLS/protocol"
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
)

// ClientConfig 配置结构（可扩展）
type ClientConfig struct {
	LocalListen string               // 本地监听地址
	Handler     func(stream protocol.Stream)
}

func StartClient(cfg *ClientConfig) error {
	// === 1. 读取配置 ===
	conf, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	// 组装 serverAddr 和 v2net.Address
	var (
		serverAddr string
		destAddr   v2net.Address
		destPort   v2net.Port
	)
	// 判断是否为域名
	if ip := net.ParseIP(conf.ServerIP); ip != nil {
		serverAddr = fmt.Sprintf("%s:%d", conf.ServerIP, conf.ServerPort)
		destAddr = v2net.IPAddress(ip)
	} else {
		serverAddr = fmt.Sprintf("%s:%d", conf.ServerIP, conf.ServerPort)
		destAddr = v2net.DomainAddress(conf.ServerIP)
	}
	destPort = v2net.Port(conf.ServerPort)
	log.Printf("client: will connect to server at %s", serverAddr)

	inbound := protocol.NewTCPInbound(cfg.LocalListen)
	if err := inbound.Listen(); err != nil {
		return err
	}
	defer inbound.Close()
	log.Printf("client: listening on %s", cfg.LocalListen)

	for {
		conn, err := inbound.Accept()
		if err != nil {
			log.Printf("client accept error: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go handleConnection(conn, serverAddr, destAddr, destPort, cfg.Handler)
	}
}

// handleConnection 处理单个连接
func handleConnection(clientConn net.Conn, serverAddr string, destAddr v2net.Address, destPort v2net.Port, handler func(protocol.Stream)) {
	defer clientConn.Close()

	// === 2. 建立到server的主连接 ===
	outbound := protocol.NewTCPOutbound(10 * time.Second)
	serverConn, err := outbound.Connect("tcp", serverAddr)
	if err != nil {
		log.Printf("client connect to server error: %v", err)
		return
	}
	defer outbound.Close()
	defer serverConn.Close()

	// === 3. 建立mux session ===
	session := protocol.NewSession(serverConn)
	defer session.Close()

	// === 4. 开一个mux子流，目标是server配置 ===
	dest := v2net.TCPDestination(destAddr, destPort)
	stream, err := session.OpenStream(dest)
	if err != nil {
		log.Printf("client open mux stream error: %v", err)
		return
	}
	defer stream.Close()

	// === 5. 双向转发 ===
	if handler != nil {
		handler(stream)
	} else {
		go func() { _, _ = io.Copy(stream, clientConn) }()
		_, _ = io.Copy(clientConn, stream)
	}
}
