package protocol

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"
	// 不需要再次导入 crypto/x509 和 os，因为它们在同一个包的 inbound.go 中已导入并使用
)

// =============================================================================
// Outbound 接口和 TCPOutbound 实现
// 此文件依赖于 protocol 包中（例如在 inbound.go 中）定义的通用结构和辅助函数。
// =============================================================================

// Outbound 抽象出口，所有出站流量都通过这个接口进行连接。
type Outbound interface {
	Connect(network, address string) (net.Conn, error)
	Close() error
}

// TCPOutbound 实现了 Outbound 接口，用于建立 TCP 连接。
// 它可以配置为进行普通的 TCP 连接，也可以进行 TLS 连接。
type TCPOutbound struct {
	timeout            time.Duration // 连接超时时间
	tlsConfig          *tls.Config   // 可选的 TLS 配置，如果为 nil 则进行普通 TCP 连接
	authToken          string        // Vyper 协议的 AuthToken，用于认证
	initialPaddingRule byte          // 客户端初始填充规则
	clientInfo         string        // 客户端信息字符串，用于伪装 HTTP User-Agent
	paddingPatterns    [][]int       // 客户端定义的填充模式列表
	mu                 sync.Mutex    // 互斥锁，用于保护 closed 字段
	closed             bool          // 标记 Outbound 是否已关闭
}

// NewTCPOutbound 创建一个新的 TCPOutbound 实例，用于普通 TCP 连接。
// timeout 参数指定了连接建立的超时时间。
func NewTCPOutbound(timeout time.Duration) *TCPOutbound {
	return &TCPOutbound{timeout: timeout}
}

// NewTLSOutbound 创建一个新的 TCPOutbound 实例，用于 TLS 连接并处理 Vyper 协议握手。
// timeout 参数指定了连接建立的超时时间。
// tlsConfig 参数包含了客户端的 TLS 配置，如服务器名称、CA 证书等。
// authToken 是 Vyper 协议的认证令牌。
// initialPaddingRule 是客户端希望使用的初始填充规则。
// clientInfo 是客户端信息字符串，用于伪装 HTTP User-Agent。
// paddingPatterns 是客户端定义的填充模式列表。
func NewTLSOutbound(timeout time.Duration, tlsConfig *tls.Config, authToken string, initialPaddingRule byte, clientInfo string, paddingPatterns [][]int) *TCPOutbound {
	return &TCPOutbound{
		timeout:            timeout,
		tlsConfig:          tlsConfig,
		authToken:          authToken,
		initialPaddingRule: initialPaddingRule,
		clientInfo:         clientInfo,
		paddingPatterns:    paddingPatterns,
	}
}

// Connect 尝试建立一个连接，并执行 Vyper 协议的客户端握手和认证。
// network 参数通常是 "tcp"，address 参数是目标地址和端口（例如 "example.com:443"）。
// 如果 Outbound 实例已关闭，则返回错误。
// 成功认证后，返回一个已完成 Vyper 握手的 net.Conn (vyperConn 实例)。
// 失败时，会关闭连接并返回错误。
func (o *TCPOutbound) Connect(network, address string) (net.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, errors.New("outbound closed")
	}

	var rawConn net.Conn
	var err error

	if o.tlsConfig != nil {
		dialer := &net.Dialer{Timeout: o.timeout}
		rawConn, err = tls.DialWithDialer(dialer, network, address, o.tlsConfig)
	} else {
		rawConn, err = net.DialTimeout(network, address, o.timeout)
	}

	if err != nil {
		return nil, fmt.Errorf("连接失败: %w", err)
	}
	log.Printf("Outbound: 已连接到 %s", address)

	// --- Vyper 协议认证阶段 ---
	// 1. 构造 AuthBlob
	authBlob := []byte(o.authToken)

	// 2. 构造 SessionToken 的伪 HTTP 请求
	currentTimeSeconds := time.Now().Unix()
	sessionTokenData := make([]byte, 8)
	binary.BigEndian.PutUint64(sessionTokenData[:], uint64(currentTimeSeconds))
	sessionTokenData = append(sessionTokenData, []byte(o.authToken)...)

	hasher := sha256.New()
	hasher.Write(sessionTokenData)
	sessionTokenHash := hasher.Sum(nil)
	calculatedSessionToken := sessionTokenHash[:4]

	base64EncodedSessionToken := base64.StdEncoding.EncodeToString(calculatedSessionToken)

	httpReqPath := fmt.Sprintf("/SessionToken/%s", base64EncodedSessionToken)
	httpReqBody := new(bytes.Buffer)
	httpReq, _ := http.NewRequest("GET", httpReqPath, nil)
	if o.tlsConfig != nil && o.tlsConfig.ServerName != "" {
		httpReq.Host = o.tlsConfig.ServerName
	} else {
		host, _, _ := net.SplitHostPort(address)
		httpReq.Host = host
	}
	httpReq.Header.Set("User-Agent", o.clientInfo)
	httpReq.Header.Set("Connection", "keep-alive")
	_ = httpReq.Write(httpReqBody)

	clientInfo := httpReqBody.String()

	// 3. 构造 Vyper Initialization Frame
	initFrame := &VyperInitializationFrame{
		AuthBlob:           authBlob,
		InitialPaddingRule: o.initialPaddingRule,
		Reserved:           []byte{0x00, 0x00, 0x00},
		ClientInfo:         clientInfo,
	}

	// 4. 写入 Vyper Initialization Frame
	if _, err := WriteVyperInitializationFrame(rawConn, initFrame); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("写入 Vyper 初始化帧失败: %w", err)
	}
	log.Printf("Outbound: Vyper 初始化帧已发送")

	// 5. 读取服务器的认证响应 (PAD_FRAME)
	responseFrame, err := ReadVyperSessionFrame(rawConn)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("读取服务器认证响应帧失败: %w", err)
	}

	if responseFrame.FrameType != 0x06 {
		rawConn.Close()
		return nil, fmt.Errorf("服务器认证响应帧类型不正确: 预期 0x06 (PAD_FRAME), 实际 %x", responseFrame.FrameType)
	}
	if len(responseFrame.Content) < 900 || len(responseFrame.Content) > 1400 {
		rawConn.Close()
		return nil, fmt.Errorf("服务器认证响应填充帧长度不符合要求: 实际 %d, 预期 900-1400", len(responseFrame.Content))
	}
	log.Printf("Outbound: Vyper 服务器认证成功，收到填充帧，长度 %d", len(responseFrame.Content))

	// 握手成功，返回一个封装了 Vyper 协议逻辑的 net.Conn
	return newVyperConn(rawConn, o.initialPaddingRule, o.paddingPatterns), nil
}

// Close 关闭出站器，阻止新的连接。
func (o *TCPOutbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	return nil
}
