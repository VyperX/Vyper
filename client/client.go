package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http" // 用于构建伪HTTP请求
	"time"

	"github.com/UltraTLS/UltraTLS/config"
	"github.com/UltraTLS/UltraTLS/protocol" // 假设 protocol 包在这里
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
)

// ClientConfig 配置结构（可扩展）
type ClientConfig struct {
	LocalListen string                  // 本地监听地址
	Handler     func(stream protocol.Stream)
}

func StartClient(cfg *ClientConfig) error {
	// === 1. 读取配置 ===
	conf, err := config.LoadClientConfig()
	if err != nil {
		log.Fatalf("无法加载配置: %v", err)
	}
	log.Printf("客户端配置加载成功: ServerIP=%s, ServerPort=%d", conf.ServerIP, conf.ServerPort)


	inbound := protocol.NewTCPInbound(cfg.LocalListen)
	if err := inbound.Listen(); err != nil {
		return fmt.Errorf("客户端监听失败: %w", err)
	}
	defer inbound.Close()
	log.Printf("客户端正在监听 %s", cfg.LocalListen)

	for {
		conn, err := inbound.Accept()
		if err != nil {
			log.Printf("客户端接受连接错误: %v", err)
			time.Sleep(time.Second) // 避免在错误循环中耗尽资源
			continue
		}
		// 为每个接受的连接启动一个 goroutine 处理
		go handleConnection(conn, conf, cfg.Handler)
	}
}

// handleConnection 处理单个客户端连接
func handleConnection(clientConn net.Conn, conf *config.Config, handler func(protocol.Stream)) {
	defer clientConn.Close()
	log.Printf("接收到本地连接，来自 %s", clientConn.RemoteAddr())

	// === 2. 建立到 Vyper 服务器的主 TLS 连接 ===
	serverAddr := fmt.Sprintf("%s:%d", conf.ServerIP, conf.ServerPort)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: conf.TLSInsecureSkipVerify,
		ServerName:         conf.TLSServerName,
		MinVersion:         tls.VersionTLS12, // 建议至少 TLS 1.2
	}

	if conf.TLSCACertPath != "" {
		caCertPool, err := protocol.LoadCACertPool(conf.TLSCACertPath)
		if err != nil {
			log.Printf("无法加载 CA 证书池: %v", err)
			return
		}
		tlsConfig.RootCAs = caCertPool
	}

	if conf.TLSClientCertPath != "" && conf.TLSClientKeyPath != "" {
		clientCert, err := tls.LoadX509KeyPair(conf.TLSClientCertPath, conf.TLSClientKeyPath)
		if err != nil {
			log.Printf("无法加载客户端证书或密钥: %v", err)
			return
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	serverConn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Printf("客户端连接到 Vyper 服务器 %s 失败: %v", serverAddr, err)
		return
	}
	defer serverConn.Close()
	log.Printf("已连接到 Vyper 服务器 %s", serverAddr)

	// === 3. Vyper 协议认证阶段 ===
	// 3.1 构造 AuthBlob
	// 假设 conf.AuthToken 在这里是直接可用的字符串，可以转换为 []byte
	authBlob := []byte(conf.AuthToken)

	// 3.2 构造 SessionToken 的伪 HTTP 请求
	// SessionToken = SHA256(当前时间戳(s) + AuthToken) 的前 4 字节
	currentTimeSeconds := time.Now().Unix()
	sessionTokenData := make([]byte, 8) // 8字节用于时间戳，确保与服务器端的 PutUint64 匹配
	binary.BigEndian.PutUint64(sessionTokenData[:], uint64(currentTimeSeconds))
	sessionTokenData = append(sessionTokenData, []byte(conf.AuthToken)...) // 拼接 AuthToken

	hasher := sha256.New()
	hasher.Write(sessionTokenData)
	sessionTokenHash := hasher.Sum(nil)
	calculatedSessionToken := sessionTokenHash[:4] // 取前 4 字节作为 SessionToken

	base64EncodedSessionToken := base64.StdEncoding.EncodeToString(calculatedSessionToken)

	// 构建一个伪 HTTP GET 请求作为 ClientInfo
	// 路径是 "/SessionToken/<Base64编码的SessionToken>"
	// 确保这是一个完整的HTTP请求，带有Host头和空行，以便服务器的 http.ReadRequest 能正确解析
	httpReqPath := fmt.Sprintf("/SessionToken/%s", base64EncodedSessionToken)
	httpReqBody := new(bytes.Buffer)
	httpReq, _ := http.NewRequest("GET", httpReqPath, nil)
	httpReq.Host = conf.TLSServerName // 使用 TLS ServerName 作为 Host 头
	httpReq.Header.Set("User-Agent", conf.ClientInfo) // 可以使用 ClientInfo 作为 User-Agent
	httpReq.Header.Set("Connection", "keep-alive")
	_ = httpReq.Write(httpReqBody) // 将请求写入 buffer

	clientInfo := httpReqBody.String() // 获取完整的 HTTP 请求字符串

	// 3.3 构造 Vyper Initialization Frame
	initFrame := &protocol.VyperInitializationFrame{
		AuthBlob:           authBlob,
		InitialPaddingRule: byte(conf.InitialPaddingRule),
		Reserved:           []byte{0x00, 0x00, 0x00}, // 3 字节保留，全部为 0x00
		ClientInfo:         clientInfo,
	}

	// 3.4 写入 Vyper Initialization Frame
	if _, err := protocol.WriteVyperInitializationFrame(serverConn, initFrame); err != nil { // 假设 WriteVyperInitializationFrame 存在于 protocol 包
		log.Printf("写入 Vyper 初始化帧失败: %v", err)
		return
	}
	log.Printf("Vyper 初始化帧已发送")

	// 3.5 读取服务器的认证响应 (PAD_FRAME)
	// 服务器认证成功后会回复一个 PAD_FRAME (900-1400字节)
	responseFrame, err := protocol.ReadVyperSessionFrame(serverConn) // 假设 ReadVyperSessionFrame 存在于 protocol 包
	if err != nil {
		log.Printf("读取服务器认证响应帧失败: %v", err)
		return
	}

	if responseFrame.FrameType != 0x06 { // 0x06 是 PAD_FRAME 的 FrameType
		log.Printf("服务器认证响应帧类型不正确: 预期 0x06 (PAD_FRAME), 实际 %x", responseFrame.FrameType)
		return
	}
	if len(responseFrame.Content) < 900 || len(responseFrame.Content) > 1400 {
		log.Printf("服务器认证响应填充帧长度不符合要求: 实际 %d, 预期 900-1400", len(responseFrame.Content))
		// 根据协议，如果长度不符，可能也是认证失败或协议异常
		return
	}
	log.Printf("Vyper 服务器认证成功，收到填充帧，长度 %d", len(responseFrame.Content))


	// === 4. 建立 Mux.Cool Session ===
	// 组装 v2net.Address 和 v2net.Port (Mux.Cool 需要这些)
	var (
		destAddr v2net.Address
		destPort v2net.Port
	)
	if ip := net.ParseIP(conf.ServerIP); ip != nil {
		destAddr = v2net.IPAddress(ip)
	} else {
		destAddr = v2net.DomainAddress(conf.ServerIP)
	}
	destPort = v2net.Port(conf.ServerPort)

	session := protocol.NewSession(serverConn) // 在这里传递认证成功后的 serverConn
	defer session.Close()
	log.Printf("Mux.Cool 会话已建立")

	// === 5. 开一个 Mux.Cool 子流，目标是服务器的内部 Mux.Cool 处理逻辑 ===
	// 对于客户端，这个子流的目标通常不是外部目的地，而是 Mux.Cool 本身。
	// 这里使用服务器的地址和端口作为 Mux 内部路由的示意目的地，具体取决于 Mux.Cool 的实现。
	// 实际场景中，客户端可能需要一个真实的代理目标来通过 OpenStream 传输。
	// 假设这里仅仅是建立一个到 Mux 协议层面的子流。
	dest := v2net.TCPDestination(destAddr, destPort) // 这是一个占位符，实际目标应由客户端的代理请求决定
	stream, err := session.OpenStream(dest)
	if err != nil {
		log.Printf("客户端打开 Mux 子流失败: %v", err)
		return
	}
	defer stream.Close()
	log.Printf("Mux.Cool 子流已打开")

	// === 6. 双向转发数据 ===
	// 将客户端连接的输入转发到 Mux 子流，并将 Mux 子流的输出转发回客户端连接
	if handler != nil {
		handler(stream) // 如果有自定义 handler，则交给 handler 处理
	} else {
		// 常规的双向数据转发
		go func() {
			_, err := io.Copy(stream, clientConn)
			if err != nil && err != io.EOF {
				log.Printf("客户端到 Mux 子流的数据转发错误: %v", err)
			}
			// 考虑在这里关闭 stream 的写入端，通知服务器不再发送数据
			// if closer, ok := stream.(io.Closer); ok { // 如果 stream 是 ReadWriteCloser
			// 	closer.CloseWrite() // 假设有 CloseWrite 方法
			// }
		}()
		_, err := io.Copy(clientConn, stream)
		if err != nil && err != io.EOF {
			log.Printf("Mux 子流到客户端的数据转发错误: %v", err)
		}
	}
	log.Printf("连接处理完成，关闭连接 %s", clientConn.RemoteAddr())
}
