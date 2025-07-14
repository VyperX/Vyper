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
	"math/rand"
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
	Handler     func(stream protocol.Stream) // Mux.Cool 层的处理函数
}

// paddingState 结构体用于管理当前连接的填充状态
type paddingState struct {
	patternIndex int          // 当前使用的填充模式索引
	pattern      [][]int      // 当前填充模式，例如 [[50, 100], [120, 200]]
	step         int          // 当前模式中的步骤
	lastPaddingTime time.Time // 上次发送填充帧的时间
}

// newPaddingState 初始化填充状态
func newPaddingState(initialRule byte, patterns [][]int) *paddingState {
	ps := &paddingState{
		lastPaddingTime: time.Now(),
	}
	// 根据 initialRule 选择模式
	if initialRule >= 0x01 && int(initialRule-1) < len(patterns) {
		ps.patternIndex = int(initialRule - 1)
		ps.pattern = patterns[ps.patternIndex]
	} else {
		// 如果 initialRule 是 0x00 (无主动填充) 或 0xFF (服务器决定)
		// 或者索引超出范围，则使用一个空模式（不主动填充）
		ps.pattern = [][]int{}
	}
	return ps
}

// generatePaddingFrame 根据当前填充状态生成一个 PAD_FRAME
// 返回 PAD_FRAME 和是否生成了帧
func (ps *paddingState) generatePaddingFrame() *protocol.VyperSessionFrame {
	if len(ps.pattern) == 0 {
		return nil // 没有主动填充模式
	}

	// 按照模式步骤生成填充
	if ps.step >= len(ps.pattern) {
		ps.step = 0 // 循环模式
	}

	minLen := ps.pattern[ps.step][0]
	maxLen := ps.pattern[ps.step][1]

	paddingLen := rand.Intn(maxLen-minLen+1) + minLen
	padData := make([]byte, paddingLen)
	rand.Read(padData) // 填充随机数据

	ps.step++
	ps.lastPaddingTime = time.Now()
	return protocol.NewPadFrame(padData)
}


func StartClient(cfg *ClientConfig) error {
	// === 1. 读取配置 ===
	conf, err := config.LoadConfig() // 使用 LoadConfig
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

	// 使用 protocol.NewTLSOutbound 建立连接，它会处理 TLS 握手
	outbound := protocol.NewTLSOutbound(time.Duration(conf.Timeout)*time.Second, tlsConfig, conf.AuthToken, byte(conf.InitialPaddingRule), conf.ClientInfo)
	serverConn, err := outbound.Connect("tcp", serverAddr)
	if err != nil {
		log.Printf("客户端连接到 Vyper 服务器 %s 失败: %v", serverAddr, err)
		return
	}
	defer outbound.Close() // 关闭 outbound 实例，但不会关闭 serverConn
	defer serverConn.Close()
	log.Printf("已连接到 Vyper 服务器 %s", serverAddr)

	// === 3. Vyper 协议认证阶段 (现在由 protocol.NewTLSOutbound 内部处理) ===
	// 如果 Connect 返回成功，则表示认证已通过

	// === 4. 建立 Mux.Cool Session ===
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

	session := protocol.NewSession(serverConn)
	defer session.Close()
	log.Printf("Mux.Cool 会话已建立")

	// === 5. 开一个 Mux.Cool 子流 ===
	dest := v2net.TCPDestination(destAddr, destPort)
	stream, err := session.OpenStream(dest)
	if err != nil {
		log.Printf("客户端打开 Mux 子流失败: %v", err)
		return
	}
	defer stream.Close()
	log.Printf("Mux.Cool 子流已打开")

	// === 6. 双向转发数据，并注入填充 ===
	// 初始化填充状态
	clientPaddingState := newPaddingState(byte(conf.InitialPaddingRule), conf.PaddingPatterns)
	serverPaddingState := newPaddingState(0x00, nil) // 客户端接收填充时，不需要主动生成，只丢弃

	// 从 clientConn 读取数据，封装成 DATA_FRAME，注入 PAD_FRAME，然后写入 stream
	go func() {
		buf := make([]byte, conf.BufferSize)
		for {
			n, err := clientConn.Read(buf)
			if n > 0 {
				// 封装为 DATA_FRAME 并写入 Mux.Cool stream
				dataFrame := &protocol.VyperSessionFrame{
					FrameType: 0x02, // DATA_FRAME
					Sequence:  0,    // 简化，实际应有递增序列号
					Content:   buf[:n],
				}
				if _, writeErr := protocol.WriteFrame(stream, dataFrame); writeErr != nil {
					log.Printf("客户端写入 DATA_FRAME 到 Mux 子流失败: %v", writeErr)
					break
				}
				// 注入填充帧
				if padFrame := clientPaddingState.generatePaddingFrame(); padFrame != nil {
					if _, writeErr := protocol.WriteFrame(stream, padFrame); writeErr != nil {
						log.Printf("客户端写入 PAD_FRAME 到 Mux 子流失败: %v", writeErr)
						// 非致命错误，可以继续
					}
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("从客户端读取数据错误: %v", err)
				}
				// 发送 CLOSE_FRAME 通知服务器流关闭
				closeFrame := &protocol.VyperSessionFrame{FrameType: 0x04, Sequence: 0, Content: []byte{}}
				if _, writeErr := protocol.WriteFrame(stream, closeFrame); writeErr != nil {
					log.Printf("客户端写入 CLOSE_FRAME 到 Mux 子流失败: %v", writeErr)
				}
				break
			}
		}
	}()

	// 从 stream 读取数据，解封装，处理 PAD_FRAME，然后写入 clientConn
	buf := make([]byte, conf.BufferSize)
	for {
		// 读取 Vyper Session Frame
		responseFrame, err := protocol.ReadVyperSessionFrame(stream)
		if err != nil {
			if err != io.EOF {
				log.Printf("从 Mux 子流读取 Vyper 帧错误: %v", err)
			}
			break
		}

		switch responseFrame.FrameType {
		case 0x02: // DATA_FRAME
			if len(responseFrame.Content) > 0 {
				if _, writeErr := clientConn.Write(responseFrame.Content); writeErr != nil {
					log.Printf("客户端写入 DATA_FRAME 内容到本地连接失败: %v", writeErr)
					break
				}
			}
		case 0x06: // PAD_FRAME
			// 收到填充帧，直接丢弃内容
			// log.Printf("客户端收到 PAD_FRAME，长度 %d", len(responseFrame.Content))
		case 0x04: // CLOSE_FRAME
			log.Printf("客户端收到 CLOSE_FRAME，关闭本地连接写入端")
			// 收到关闭帧，关闭本地连接的写入端
			if closer, ok := clientConn.(interface{ CloseWrite() error }); ok {
				closer.CloseWrite()
			} else {
				clientConn.Close() // 如果不支持 CloseWrite，则直接关闭整个连接
			}
			break // 退出读取循环
		case 0x05: // ERR_FRAME
			log.Printf("客户端收到 ERR_FRAME: %s", string(responseFrame.Content))
			break // 收到错误帧，退出读取循环
		default:
			log.Printf("客户端收到未知帧类型: %x", responseFrame.FrameType)
			// 可以选择关闭连接或忽略
		}
	}

	log.Printf("连接处理完成，关闭连接 %s", clientConn.RemoteAddr())
}
