package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http" // 用于完整的HTTP请求和响应处理
	"net/url" // 用于解析URL
	"time"

	"github.com/UltraTLS/UltraTLS/protocol" // 假设 protocol 包在这里
	"github.com/UltraTLS/UltraTLS/config"
	"github.com/v2fly/v2ray-core/v5/common/net" // 假设这个包可用
)

// ServerConfig 用于启动服务器的配置
type ServerConfig struct {
	ListenAddr    string
	Handler       func(stream protocol.Stream) // Mux.Cool 层的处理函数
	VyperConfig   *config.ServerConfig // 包含 Vyper 协议特有配置
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
	} else if initialRule == 0xFF && len(patterns) > 0 {
		// 如果客户端请求服务器决定，且服务器有模式，则选择第一个作为默认
		ps.patternIndex = 0
		ps.pattern = patterns[0]
	} else {
		// 否则使用空模式（不主动填充）
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


// StartServer 启动 Vyper 服务器
func StartServer(cfg *ServerConfig) error {
	// 加载 TLS 配置
	tlsCert, err := tls.LoadX509KeyPair(cfg.VyperConfig.TLSCertPath, cfg.VyperConfig.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("无法加载 TLS 证书或密钥: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12, // 建议至少 TLS 1.2
	}

	if cfg.VyperConfig.TLSClientAuth {
		clientCACertPool, err := protocol.LoadCACertPool(cfg.VyperConfig.TLSClientCaCertPath)
		if err != nil {
			return fmt.Errorf("无法加载客户端 CA 证书池: %w", err)
		}
		tlsConfig.ClientCAs = clientCACertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// 使用 protocol.NewTLSInbound 监听连接，它会处理 TLS 握手和 Vyper 认证
	inbound := protocol.NewTLSInbound(cfg.ListenAddr, tlsConfig, cfg.VyperConfig.AuthToken, cfg.VyperConfig.FallbackAddress)
	if err := inbound.Listen(); err != nil {
		return fmt.Errorf("服务器 TLS 监听失败: %w", err)
	}
	defer inbound.Close()

	log.Printf("Vyper 服务器正在监听 %s", cfg.ListenAddr)

	for {
		// Accept 方法现在会处理 Vyper 认证，成功后返回已认证的 net.Conn
		conn, err := inbound.Accept()
		if err != nil {
			log.Printf("服务器接受连接错误或 Vyper 认证失败: %v", err)
			// Accept 内部已经处理了回退或关闭连接，这里只需继续循环
			time.Sleep(time.Second) // 避免在错误循环中耗尽资源
			continue
		}
		// 认证成功后，继续处理 Mux.Cool 会话和子流
		go handleAuthenticatedConnection(conn, cfg.Handler, cfg.VyperConfig.PaddingPatterns)
	}
}

// handleAuthenticatedConnection 处理已通过 Vyper 认证的连接
func handleAuthenticatedConnection(rawConn net.Conn, handler func(stream protocol.Stream), serverPaddingPatterns [][]int) {
	defer rawConn.Close()

	log.Printf("接收到来自 %s 的 Vyper 认证成功连接", rawConn.RemoteAddr())

	// === 建立 Mux.Cool Session ===
	session := protocol.NewSession(rawConn)
	defer session.Close()
	log.Printf("Mux.Cool 会话已建立 (%s)", rawConn.RemoteAddr())

	// === 持续接受 Mux.Cool 子流 ===
	for {
		stream, _, err := session.AcceptStream()
		if err != nil {
			log.Printf("服务器接受 Mux 子流错误 (%s): %v", rawConn.RemoteAddr(), err)
			break
		}
		log.Printf("服务器接受到新的 Mux 子流 (%s)", rawConn.RemoteAddr())

		// 为每个 Mux 子流启动一个 goroutine 处理双向数据转发和填充
		go handleMuxStream(stream, handler, serverPaddingPatterns)
	}
}

// handleMuxStream 处理单个 Mux.Cool 子流的双向数据转发和填充
func handleMuxStream(stream protocol.Stream, handler func(protocol.Stream), serverPaddingPatterns [][]int) {
	defer stream.Close()

	// 初始化填充状态
	serverPaddingState := newPaddingState(0x01, serverPaddingPatterns) // 服务器主动填充，使用第一个模式
	clientPaddingState := newPaddingState(0x00, nil) // 服务器接收客户端填充时，不需要主动生成，只丢弃

	// 从 Mux.Cool stream 读取数据，解封装，处理 PAD_FRAME，然后写入 handler (或目标连接)
	go func() {
		buf := make([]byte, 4096) // 使用一个默认缓冲区大小
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
					// 将数据传递给上层 handler
					if _, writeErr := handler(stream).Write(responseFrame.Content); writeErr != nil { // 假设 handler 返回一个 io.Writer
						log.Printf("服务器写入 DATA_FRAME 内容到 handler 失败: %v", writeErr)
						break
					}
				}
			case 0x06: // PAD_FRAME
				// 收到填充帧，直接丢弃内容
				// log.Printf("服务器收到 PAD_FRAME，长度 %d", len(responseFrame.Content))
			case 0x04: // CLOSE_FRAME
				log.Printf("服务器收到 CLOSE_FRAME，关闭 Mux 子流写入端")
				// 收到关闭帧，关闭 Mux 子流的写入端
				if closer, ok := stream.(interface{ CloseWrite() error }); ok {
					closer.CloseWrite()
				} else {
					stream.Close() // 如果不支持 CloseWrite，则直接关闭整个流
				}
				break // 退出读取循环
			case 0x01: // REQ_FRAME (客户端请求代理目标)
				// 这是 Mux.Cool 的子流，REQ_FRAME 应该由 Mux.Cool 处理，
				// 但如果 Vyper 协议层也需要处理，则在这里处理。
				// 鉴于 Mux.Cool 已经处理了目标地址，这里可能不需要额外处理 REQ_FRAME
				// 如果 handler 是一个负责代理的函数，它会处理这个。
				log.Printf("服务器收到 REQ_FRAME (可能由 Mux.Cool 处理): %s", string(responseFrame.Content))
			case 0x05: // ERR_FRAME
				log.Printf("服务器收到 ERR_FRAME: %s", string(responseFrame.Content))
				break // 收到错误帧，退出读取循环
			default:
				log.Printf("服务器收到未知帧类型: %x", responseFrame.FrameType)
			}
		}
	}()

	// 从 handler (或目标连接) 读取数据，封装成 DATA_FRAME，注入 PAD_FRAME，然后写入 Mux.Cool stream
	// 这个循环需要从 handler 提供的源读取数据，然后将其封装为 Vyper 帧写入 stream
	buf := make([]byte, 4096) // 使用一个默认缓冲区大小
	for {
		n, err := handler(stream).Read(buf) // 假设 handler 返回一个 io.Reader
		if n > 0 {
			// 封装为 DATA_FRAME 并写入 Mux.Cool stream
			dataFrame := &protocol.VyperSessionFrame{
				FrameType: 0x02, // DATA_FRAME
				Sequence:  0,    // 简化，实际应有递增序列号
				Content:   buf[:n],
			}
			if _, writeErr := protocol.WriteFrame(stream, dataFrame); writeErr != nil {
				log.Printf("服务器写入 DATA_FRAME 到 Mux 子流失败: %v", writeErr)
				break
			}
			// 注入填充帧
			if padFrame := serverPaddingState.generatePaddingFrame(); padFrame != nil {
				if _, writeErr := protocol.WriteFrame(stream, padFrame); writeErr != nil {
					log.Printf("服务器写入 PAD_FRAME 到 Mux 子流失败: %v", writeErr)
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("从 handler 读取数据错误: %v", err)
			}
			// 发送 CLOSE_FRAME 通知客户端流关闭
			closeFrame := &protocol.VyperSessionFrame{FrameType: 0x04, Sequence: 0, Content: []byte{}}
			if _, writeErr := protocol.WriteFrame(stream, closeFrame); writeErr != nil {
				log.Printf("服务器写入 CLOSE_FRAME 到 Mux 子流失败: %v", writeErr)
			}
			break
		}
	}
	log.Printf("Mux 子流处理完成 (%s)", rawConn.RemoteAddr())
}

// handleFallback 处理认证失败后的 HTTP Fallback
// 它将客户端的请求转发到 fallbackAddr，并将响应写回客户端。
func handleFallback(conn net.Conn, fallbackAddr string) {
	log.Printf("触发 Fallback 到 %s", fallbackAddr)
	defer conn.Close() // 确保回退连接最终被关闭

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("读取 Fallback HTTP 请求失败 (%s): %v", conn.RemoteAddr(), err)
		sendHTTPError(conn, http.StatusBadRequest, "Invalid HTTP Request")
		return
	}

	fallbackURL, err := url.Parse(fallbackAddr)
	if err != nil {
		log.Printf("解析 Fallback URL 失败 (%s): %v", conn.RemoteAddr(), err)
		sendHTTPError(conn, http.StatusInternalServerError, "Server Fallback Misconfiguration")
		return
	}

	req.RequestURI = ""
	req.URL.Host = fallbackURL.Host
	req.URL.Scheme = fallbackURL.Scheme
	req.URL.Opaque = fallbackURL.Opaque

	client := &http.Client{
		Timeout: 10 * time.Second, // Fallback 请求的超时
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("转发 Fallback 请求到 %s 失败 (%s): %v", fallbackAddr, conn.RemoteAddr(), err)
		sendHTTPError(conn, http.StatusBadGateway, "Fallback Target Unreachable")
		return
	}
	defer resp.Body.Close()

	err = resp.Write(conn)
	if err != nil {
		log.Printf("写入 Fallback 响应到客户端失败 (%s): %v", conn.RemoteAddr(), err)
	}

	log.Printf("已处理 Fallback 请求，关闭连接 %s", conn.RemoteAddr())
}

// sendHTTPError 向连接发送一个简单的 HTTP 错误响应
func sendHTTPError(w io.Writer, statusCode int, message string) {
	resp := &http.Response{
		Status:     http.StatusText(statusCode),
		StatusCode: statusCode,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(message + "\n")),
	}
	resp.Header.Set("Connection", "close")
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(message)+1))

	err := resp.Write(w)
	if err != nil {
		log.Printf("发送 HTTP 错误响应失败: %v", err)
	}
}
