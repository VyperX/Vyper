package protocol

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// =============================================================================
// Vyper 协议相关的通用结构和辅助函数。
// 这些定义在此文件中，并可供同一 protocol 包中的其他文件（如 outbound.go）使用。
// =============================================================================

// Stream 是 Mux.Cool 的子流接口。
// 假设 Mux.Cool 提供了这个接口。
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
}

// Session 是 Mux.Cool 的会话接口。
// 假设 Mux.Cool 提供了这个接口。
type Session interface {
	OpenStream(dest interface{}) (Stream, error) // dest 通常是 v2net.Destination
	AcceptStream() (Stream, []byte, error)
	Close() error
}

// NewSession 创建一个新的 Mux.Cool 会话 (模拟实现)。
// 实际应用中，这里会调用 Mux.Cool 库的会话初始化函数。
func NewSession(conn net.Conn) Session {
	return &mockMuxSession{conn: conn}
}

// mockMuxSession 是 Mux.Cool Session 接口的模拟实现。
type mockMuxSession struct {
	conn net.Conn
}

func (m *mockMuxSession) OpenStream(dest interface{}) (Stream, error) {
	// 模拟打开子流，实际会返回 Mux.Cool 的 Stream 实例
	return &mockMuxStream{conn: m.conn}, nil
}

func (m *mockMuxSession) AcceptStream() (Stream, []byte, error) {
	// 模拟接受子流，实际会返回 Mux.Cool 的 Stream 实例和可能的元数据
	return &mockMuxStream{conn: m.conn}, nil, nil
}

func (m *mockMuxSession) Close() error {
	// 模拟关闭 Mux.Cool 会话，实际会关闭底层连接
	return m.conn.Close()
}

// mockMuxStream 是 Mux.Cool Stream 接口的模拟实现。
type mockMuxStream struct {
	conn io.ReadWriter
}

func (m *mockMuxStream) Read(b []byte) (n int, err error) {
	return m.conn.Read(b)
}

func (m *mockMuxStream) Write(b []byte) (n int, err error) {
	return m.conn.Write(b)
}

func (m *mockMuxStream) Close() error {
	// 模拟关闭 Mux.Cool 子流，通常不关闭底层连接
	return nil
}

// VyperInitializationFrame 定义了 Vyper 协议的初始化帧结构。
// 客户端在 TLS 握手后立即发送此帧进行认证和参数协商。
type VyperInitializationFrame struct {
	AuthBlob           []byte // 认证数据块
	InitialPaddingRule byte   // 初始填充规则
	Reserved           []byte // 3 字节保留字段
	ClientInfo         string // 客户端信息，此处被重用于承载 SessionToken 的伪 HTTP 请求
}

// VyperSessionFrame 定义了 Vyper 协议的通用会话帧结构。
// 所有 Vyper 会话数据（请求、数据、流控、关闭、错误、填充）都封装在此帧中。
type VyperSessionFrame struct {
	FrameType byte   // 帧类型
	Sequence  uint32 // 序列号
	Content   []byte // 帧内容
}

// LoadCACertPool 从 PEM 编码的 CA 证书文件路径加载一个 *x509.CertPool。
// 用于验证 TLS 证书链。
func LoadCACertPool(caCertPath string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("无法读取 CA 证书文件 '%s': %w", caCertPath, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("无法从 PEM 解析 CA 证书文件 '%s'", caCertPath)
	}
	return caCertPool, nil
}

// ReadVyperInitializationFrame 从给定的 io.Reader 中读取一个完整的 Vyper Initialization Frame。
// 它严格遵循 Vyper 协议规范 Section 4.2 中定义的字节格式和顺序。
func ReadVyperInitializationFrame(r io.Reader) (*VyperInitializationFrame, error) {
	var initFrame VyperInitializationFrame

	var authBlobLen uint16
	if err := binary.Read(r, binary.BigEndian, &authBlobLen); err != nil {
		return nil, fmt.Errorf("读取 AuthBlob Length 失败: %w", err)
	}

	initFrame.AuthBlob = make([]byte, authBlobLen)
	if _, err := io.ReadFull(r, initFrame.AuthBlob); err != nil {
		return nil, fmt.Errorf("读取 AuthBlob 失败: %w", err)
	}

	if err := binary.Read(r, binary.BigEndian, &initFrame.InitialPaddingRule); err != nil {
		return nil, fmt.Errorf("读取 InitialPaddingRule 失败: %w", err)
	}

	initFrame.Reserved = make([]byte, 3)
	if _, err := io.ReadFull(r, initFrame.Reserved); err != nil {
		return nil, fmt.Errorf("读取 Reserved 字段失败: %w", err)
	}

	var clientInfoLen uint16
	if err := binary.Read(r, binary.BigEndian, &clientInfoLen); err != nil {
		return nil, fmt.Errorf("读取 ClientInfo Length 失败: %w", err)
	}

	clientInfoBytes := make([]byte, clientInfoLen)
	if _, err := io.ReadFull(r, clientInfoBytes); err != nil {
		return nil, fmt.Errorf("读取 ClientInfo 失败: %w", err)
	}
	initFrame.ClientInfo = string(clientInfoBytes)

	return &initFrame, nil
}

// WriteVyperInitializationFrame 将一个 VyperInitializationFrame 写入到 io.Writer。
// 它严格遵循 Vyper 协议规范 Section 4.2 中定义的字节格式和顺序。
func WriteVyperInitializationFrame(w io.Writer, frame *VyperInitializationFrame) (int, error) {
	totalN := 0

	authBlobLen := uint16(len(frame.AuthBlob))
	if err := binary.Write(w, binary.BigEndian, authBlobLen); err != nil {
		return totalN, fmt.Errorf("写入 AuthBlob Length 失败: %w", err)
	}
	totalN += 2

	n, err := w.Write(frame.AuthBlob)
	if err != nil {
		return totalN + n, fmt.Errorf("写入 AuthBlob 失败: %w", err)
	}
	totalN += n

	if err := binary.Write(w, binary.BigEndian, frame.InitialPaddingRule); err != nil {
		return totalN, fmt.Errorf("写入 InitialPaddingRule 失败: %w", err)
	}
	totalN += 1

	n, err = w.Write(frame.Reserved)
	if err != nil {
		return totalN + n, fmt.Errorf("写入 Reserved 字段失败: %w", err)
	}
	totalN += n

	clientInfoLen := uint16(len(frame.ClientInfo))
	if err := binary.Write(w, binary.BigEndian, clientInfoLen); err != nil {
		return totalN, fmt.Errorf("写入 ClientInfo Length 失败: %w", err)
	}
	totalN += 2

	n, err = w.Write([]byte(frame.ClientInfo))
	if err != nil {
		return totalN + n, fmt.Errorf("写入 ClientInfo 失败: %w", err)
	}
	totalN += n

	return totalN, nil
}

// Base64Decode 对 Base64 标准编码的字符串进行解码，返回原始字节切片。
func Base64Decode(s string) ([]byte, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("Base64 解码失败: %w", err)
	}
	return decodedBytes, nil
}

// NewPadFrame 创建一个 Vyper PAD_FRAME。
// PAD_FRAME 用于在协议中插入填充数据以增加流量的混淆性。
func NewPadFrame(content []byte) *VyperSessionFrame {
	return &VyperSessionFrame{
		FrameType: 0x06, // PAD_FRAME 的 FrameType 定义为 0x06
		Sequence:  0,    // 对于 PAD_FRAME，Sequence 字段通常可以为 0 或不重要
		Content:   content,
	}
}

// WriteFrame 将一个 VyperSessionFrame 写入到 io.Writer。
// 它严格遵循 Vyper 协议规范 Section 5.1 中定义的字节格式和顺序。
func WriteFrame(w io.Writer, frame *VyperSessionFrame) (int, error) {
	// 帧头包含 FrameType (1B) + Sequence (4B) + Content Length (2B) = 7 字节
	header := make([]byte, 7)
	header[0] = frame.FrameType
	binary.BigEndian.PutUint32(header[1:5], frame.Sequence)
	binary.BigEndian.PutUint16(header[5:7], uint16(len(frame.Content))) // Content Length 是 Content 的长度

	n, err := w.Write(header) // 写入帧头
	if err != nil {
		return n, fmt.Errorf("写入帧头失败: %w", err)
	}

	contentN, err := w.Write(frame.Content) // 写入帧内容
	if err != nil {
		return n + contentN, fmt.Errorf("写入帧内容失败: %w", err)
	}

	return n + contentN, nil // 返回总写入字节数
}

// ReadVyperSessionFrame 从 io.Reader 读取一个完整的 VyperSessionFrame。
// 它遵循 Vyper 协议中会话帧的字节格式。
func ReadVyperSessionFrame(r io.Reader) (*VyperSessionFrame, error) {
	frame := &VyperSessionFrame{}
	header := make([]byte, 7) // FrameType (1B) + Sequence (4B) + Content Length (2B)

	// 读取帧头
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("读取会话帧头失败: %w", err)
	}

	frame.FrameType = header[0]
	frame.Sequence = binary.BigEndian.Uint32(header[1:5])
	contentLen := binary.BigEndian.Uint16(header[5:7])

	// 读取帧内容
	if contentLen > 0 {
		frame.Content = make([]byte, contentLen)
		if _, err := io.ReadFull(r, frame.Content); err != nil {
			return nil, fmt.Errorf("读取会话帧内容失败 (预期长度 %d): %w", contentLen, err)
		}
	} else {
		frame.Content = []byte{} // 内容长度为0时，设为空字节切片
	}

	return frame, nil
}

// --- Vyper 协议连接封装 (vyperConn) ---
// vyperConn 封装了底层的 net.Conn，并处理 Vyper 协议的帧读写和填充逻辑。
type vyperConn struct {
	net.Conn // 嵌入底层连接，实现大部分 net.Conn 接口方法

	reader *bufio.Reader // 带缓冲的读取器，用于高效读取底层连接

	// 写入相关
	writeMutex   sync.Mutex    // 保护写入操作
	paddingState *paddingState // 填充状态，用于出站流量

	// 读取相关
	readBuffer *bytes.Buffer // 用于存储已解封装的 Vyper DATA_FRAME 内容
	readMutex  sync.Mutex    // 保护读取操作
}

// paddingState 结构体用于管理当前连接的填充状态
type paddingState struct {
	allPatterns      [][]int   // 所有可用的填充模式
	currentPatternIndex int    // 当前选定的模式索引
	currentStepInPattern int   // 当前模式中的步骤
	lastPaddingTime  time.Time // 上次发送填充帧的时间
	// paddingInterval  time.Duration // 可选：强制填充的最小时间间隔，用于空闲时发送填充
}

// newPaddingState 初始化填充状态
// initialRule: 客户端请求或服务器决定的初始填充规则
// allPatterns: 客户端或服务器配置的所有填充模式
func newPaddingState(initialRule byte, allPatterns [][]int) *paddingState {
	ps := &paddingState{
		allPatterns:     allPatterns,
		lastPaddingTime: time.Now(),
		// paddingInterval: time.Millisecond * 100, // 示例：每 100ms 尝试填充一次
	}

	if initialRule >= 0x01 && int(initialRule-1) < len(allPatterns) {
		ps.currentPatternIndex = int(initialRule - 1)
	} else if initialRule == 0xFF && len(allPatterns) > 0 {
		// 如果客户端请求服务器决定 (0xFF) 且服务器有模式，则默认使用第一个模式
		ps.currentPatternIndex = 0
	} else {
		// 否则（0x00 或无效索引），表示无主动填充
		ps.currentPatternIndex = -1
	}
	return ps
}

// generatePaddingFrame 根据当前填充状态生成一个 PAD_FRAME。
// 返回 nil 表示不生成填充帧。
// 详细填充逻辑：
// 1. 检查是否启用了主动填充（currentPatternIndex != -1 且有可用模式）。
// 2. 根据当前模式步骤 (currentStepInPattern) 选择 min_length 和 max_length。
// 3. 生成一个在该范围内的随机长度。
// 4. 生成随机填充数据。
// 5. 更新步骤和上次填充时间。
func (ps *paddingState) generatePaddingFrame() *VyperSessionFrame {
	if ps.currentPatternIndex == -1 || len(ps.allPatterns) == 0 {
		return nil // 没有主动填充模式或没有配置模式
	}

	selectedPattern := ps.allPatterns[ps.currentPatternIndex]
	if len(selectedPattern) == 0 {
		return nil // 选定的模式为空
	}

	// 循环模式中的步骤
	if ps.currentStepInPattern >= len(selectedPattern) {
		ps.currentStepInPattern = 0
	}

	minLen := selectedPattern[ps.currentStepInPattern][0]
	maxLen := selectedPattern[ps.currentStepInPattern][1]

	// 确保 minLen 不大于 maxLen，防止 rand.Intn 报错
	if minLen > maxLen {
		minLen = maxLen // 修正不合理配置
	}

	// 生成随机长度的填充数据
	paddingLen := rand.Intn(maxLen-minLen+1) + minLen
	padData := make([]byte, paddingLen)
	rand.Read(padData) // 填充随机数据

	ps.currentStepInPattern++
	ps.lastPaddingTime = time.Now()
	return NewPadFrame(padData)
}

// newVyperConn 创建一个新的 vyperConn 实例。
// rawConn 是底层已建立的 TCP/TLS 连接。
// initialRule 是 Vyper 协议的初始填充规则。
// allPatterns 是所有可用的填充模式。
func newVyperConn(rawConn net.Conn, initialRule byte, allPatterns [][]int) *vyperConn {
	vc := &vyperConn{
		Conn:         rawConn,
		reader:       bufio.NewReader(rawConn),
		writeBuffer:  new(bytes.Buffer),
		readBuffer:   new(bytes.Buffer),
		paddingState: newPaddingState(initialRule, allPatterns),
	}
	return vc
}

// Read 从 Vyper 连接中读取数据。它会解析 Vyper 帧，跳过填充帧，并返回 DATA_FRAME 的内容。
// 此方法会阻塞直到有数据可用或发生错误。
// 详细读取逻辑：
// 1. 首先检查内部 readBuffer 是否有已解封装的数据。如果有，直接返回。
// 2. 如果没有，则进入循环，从底层连接读取 Vyper 会话帧。
// 3. 根据 FrameType 进行处理：
//    - DATA_FRAME (0x02): 将内容写入 readBuffer，然后从 readBuffer 读取到传入的 b。
//    - PAD_FRAME (0x06): 丢弃内容，继续循环读取下一个帧（实现混淆）。
//    - CLOSE_FRAME (0x04): 返回 io.EOF，表示对方关闭了写入端。
//    - ERR_FRAME (0x05): 返回一个错误，包含错误信息。
//    - REQ_FRAME (0x01) / FLOW_FRAME (0x03) 及其他未知帧：根据协议栈，这些帧通常由 Mux.Cool 处理。
//      如果在 VyperConn 层面收到，说明协议异常或 Mux.Cool 未能正确处理，返回错误。
func (vc *vyperConn) Read(b []byte) (n int, err error) {
	vc.readMutex.Lock()
	defer vc.readMutex.Unlock()

	// 如果内部读取缓冲区有数据，优先读取
	if vc.readBuffer.Len() > 0 {
		return vc.readBuffer.Read(b)
	}

	// 否则，从底层连接读取 Vyper 帧并处理
	for {
		frame, err := ReadVyperSessionFrame(vc.reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF // 底层连接关闭
			}
			return 0, fmt.Errorf("读取 Vyper 会话帧失败: %w", err)
		}

		switch frame.FrameType {
		case 0x02: // DATA_FRAME
			// 收到数据帧，将其内容写入内部缓冲区
			vc.readBuffer.Write(frame.Content)
			// 然后从缓冲区读取到传入的 b
			return vc.readBuffer.Read(b)
		case 0x06: // PAD_FRAME
			// 收到填充帧，直接丢弃内容，继续读取下一个帧
			continue
		case 0x04: // CLOSE_FRAME
			// 收到关闭帧，表示对方已关闭写入端
			return 0, io.EOF // 返回 EOF 信号流结束
		case 0x05: // ERR_FRAME
			// 收到错误帧
			return 0, fmt.Errorf("Vyper 协议错误帧: %s", string(frame.Content))
		case 0x01: // REQ_FRAME (此帧应由 Mux.Cool 处理，不应在 VyperConn 的 Read 中出现)
			// 根据协议栈，REQ_FRAME 应该在 Mux.Cool 层被处理，
			// VyperConn 应该只看到 DATA_FRAME, PAD_FRAME, CLOSE_FRAME, ERR_FRAME。
			// 如果在这里收到，说明上层协议处理有误。
			return 0, fmt.Errorf("Vyper 协议异常: 在数据流中收到 REQ_FRAME (应由 Mux.Cool 处理)")
		case 0x03: // FLOW_FRAME (此帧应由 Mux.Cool 处理，不应在 VyperConn 的 Read 中出现)
			// FLOW_FRAME 也应由 Mux.Cool 处理。
			return 0, fmt.Errorf("Vyper 协议异常: 在数据流中收到 FLOW_FRAME (应由 Mux.Cool 处理)")
		default:
			return 0, fmt.Errorf("Vyper 协议异常: 未知帧类型 %x", frame.FrameType)
		}
	}
}

// Write 将数据写入 Vyper 连接。它会将数据封装成 DATA_FRAME，并根据填充策略注入 PAD_FRAME。
// 此方法会阻塞直到数据写入完成或发生错误。
// 详细写入逻辑：
// 1. 将传入的数据 b 封装成一个 DATA_FRAME。
// 2. 将 DATA_FRAME 写入到底层连接。
// 3. 根据 paddingState 尝试生成一个 PAD_FRAME。
// 4. 如果生成了 PAD_FRAME，将其写入到底层连接（实现随机交错）。
// 5. 返回写入的原始数据长度。
func (vc *vyperConn) Write(b []byte) (n int, err error) {
	vc.writeMutex.Lock()
	defer vc.writeMutex.Unlock()

	// 1. 写入 DATA_FRAME
	dataFrame := &VyperSessionFrame{
		FrameType: 0x02, // DATA_FRAME
		Sequence:  0,    // 简化：实际应用中应维护递增序列号
		Content:   b,
	}
	if _, err := WriteFrame(vc.Conn, dataFrame); err != nil {
		return 0, fmt.Errorf("写入 DATA_FRAME 失败: %w", err)
	}

	// 2. 注入 PAD_FRAME (随机交错)
	// 根据协议，PAD_FRAME 可以随机交错。这里选择在每次写入 DATA_FRAME 后尝试注入一个。
	// 这实现了“随机交错”和“缺乏停止计数器”的特性。
	if padFrame := vc.paddingState.generatePaddingFrame(); padFrame != nil {
		if _, err := WriteFrame(vc.Conn, padFrame); err != nil {
			// 填充帧写入失败通常不是致命错误，记录日志并继续
			log.Printf("VyperConn: 写入 PAD_FRAME 失败: %v", err)
		}
	}

	return len(b), nil
}

// Close 关闭 Vyper 连接。它会发送一个 CLOSE_FRAME，然后关闭底层连接。
func (vc *vyperConn) Close() error {
	vc.writeMutex.Lock()
	defer vc.writeMutex.Unlock()

	closeFrame := &VyperSessionFrame{FrameType: 0x04, Sequence: 0, Content: []byte{}}
	if _, err := WriteFrame(vc.Conn, closeFrame); err != nil {
		log.Printf("VyperConn: 发送 CLOSE_FRAME 失败: %v", err)
		// 即使发送失败，也要尝试关闭底层连接
	}
	return vc.Conn.Close()
}

// LocalAddr 返回底层连接的本地网络地址。
func (vc *vyperConn) LocalAddr() net.Addr {
	return vc.Conn.LocalAddr()
}

// RemoteAddr 返回底层连接的远程网络地址。
func (vc *vyperConn) RemoteAddr() net.Addr {
	return vc.Conn.RemoteAddr()
}

// SetDeadline 设置底层连接的读写截止时间。
func (vc *vyperConn) SetDeadline(t time.Time) error {
	return vc.Conn.SetDeadline(t)
}

// SetReadDeadline 设置底层连接的读取截止时间。
func (vc *vyperConn) SetReadDeadline(t time.Time) error {
	return vc.Conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置底层连接的写入截止时间。
func (vc *vyperConn) SetWriteDeadline(t time.Time) error {
	return vc.Conn.SetWriteDeadline(t)
}

// =============================================================================
// Inbound 接口和 TCPInbound 实现
// =============================================================================

// Inbound 抽象入口，所有入站流量都通过这个接口进行监听和接受。
type Inbound interface {
	Listen() error
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// TCPInbound 实现了 Inbound 接口，用于监听和接受 TCP 连接。
// 它可以配置为进行普通的 TCP 监听，也可以进行 TLS 监听。
type TCPInbound struct {
	addr            string          // 监听地址
	listener        net.Listener    // 底层监听器
	tlsConfig       *tls.Config     // 可选的 TLS 配置，如果为 nil 则进行普通 TCP 监听
	authToken       string          // Vyper 协议的 AuthToken，用于认证
	fallbackAddress string          // 认证失败时的 L7 回退地址
	paddingPatterns [][]int         // 服务器定义的填充模式列表
	mu              sync.Mutex      // 互斥锁，用于保护 closed 字段和 listener
	closed          bool            // 标记 Inbound 是否已关闭
}

// NewTCPInbound 创建一个新的 TCPInbound 实例，用于普通 TCP 监听。
// addr 参数指定了监听的网络地址（例如 "0.0.0.0:8080"）。
func NewTCPInbound(addr string) *TCPInbound {
	return &TCPInbound{addr: addr}
}

// NewTLSInbound 创建一个新的 TCPInbound 实例，用于 TLS 监听并处理 Vyper 协议握手。
// addr 参数指定了监听的网络地址。
// tlsConfig 参数包含了服务器的 TLS 证书、私钥等配置。
// authToken 是 Vyper 协议的认证令牌。
// fallbackAddress 是认证失败时的 HTTP 回退地址。
// paddingPatterns 是服务器定义的填充模式列表。
func NewTLSInbound(addr string, tlsConfig *tls.Config, authToken, fallbackAddress string, paddingPatterns [][]int) *TCPInbound {
	return &TCPInbound{
		addr:            addr,
		tlsConfig:       tlsConfig,
		authToken:       authToken,
		fallbackAddress: fallbackAddress,
		paddingPatterns: paddingPatterns,
	}
}

// Listen 开始监听 TCP 连接。
// 如果 Inbound 实例已经关闭，则返回错误。
// 如果配置了 tlsConfig，则进行 TLS 监听；否则进行普通 TCP 监听。
func (i *TCPInbound) Listen() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return errors.New("inbound closed")
	}

	var ln net.Listener
	var err error

	if i.tlsConfig != nil {
		ln, err = tls.Listen("tcp", i.addr, i.tlsConfig)
	} else {
		ln, err = net.Listen("tcp", i.addr)
	}

	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}
	i.listener = ln
	return nil
}

// Accept 接受一个传入的连接，并执行 Vyper 协议的服务器端握手和认证。
// 如果监听器尚未初始化，则返回错误。
// 成功认证后，返回一个已完成 Vyper 握手的 net.Conn (vyperConn 实例)。
// 失败时，会根据配置尝试回退或直接关闭连接。
func (i *TCPInbound) Accept() (net.Conn, error) {
	if i.listener == nil {
		return nil, errors.New("inbound not listening")
	}

	rawConn, err := i.listener.Accept()
	if err != nil {
		return nil, err
	}

	log.Printf("Inbound: 接收到来自 %s 的新连接", rawConn.RemoteAddr())

	// --- Vyper 协议认证阶段 ---
	// 1. 读取客户端发送的 Vyper Initialization Frame
	initFrame, err := ReadVyperInitializationFrame(rawConn)
	if err != nil {
		log.Printf("Inbound: 读取 Vyper 初始化帧失败 (%s): %v", rawConn.RemoteAddr(), err)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, fmt.Errorf("Vyper 握手失败: %w", err)
	}

	// 2. 验证 AuthBlob
	if string(initFrame.AuthBlob) != i.authToken {
		log.Printf("Inbound: AuthBlob 验证失败 (%s): AuthBlob不匹配", rawConn.RemoteAddr())
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, errors.New("Vyper 握手失败: AuthBlob 不匹配")
	}

	// 3. 计算并验证 SessionToken
	currentTimeSeconds := time.Now().Unix()
	sessionTokenData := make([]byte, 8)
	binary.BigEndian.PutUint64(sessionTokenData[:], uint64(currentTimeSeconds))
	sessionTokenData = append(sessionTokenData, []byte(i.authToken)...)

	hasher := sha256.New()
	hasher.Write(sessionTokenData)
	sessionTokenHash := hasher.Sum(nil)
	expectedSessionToken := sessionTokenHash[:4]

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(initFrame.ClientInfo))))
	if err != nil {
		log.Printf("Inbound: 解析 Vyper Initialization Frame 中的伪 HTTP 请求失败 (%s): %v", rawConn.RemoteAddr(), err)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, fmt.Errorf("Vyper 握手失败: 无法解析伪 HTTP 请求: %w", err)
	}

	if req.Method != "GET" {
		log.Printf("Inbound: 伪 HTTP 请求方法不是 GET (%s): %s", rawConn.RemoteAddr(), req.Method)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, errors.New("Vyper 握手失败: 伪 HTTP 请求方法不正确")
	}

	if !bytes.HasPrefix([]byte(req.URL.Path), []byte("/SessionToken/")) {
		log.Printf("Inbound: 伪 HTTP 请求路径格式不正确 (%s): %s", rawConn.RemoteAddr(), req.URL.Path)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, errors.New("Vyper 握手失败: 伪 HTTP 请求路径格式不正确")
	}

	base64EncodedToken := req.URL.Path[len("/SessionToken/"):]
	decodedToken, decodeErr := Base64Decode(base64EncodedToken)
	if decodeErr != nil {
		log.Printf("Inbound: SessionToken Base64解码失败 (%s): %v", rawConn.RemoteAddr(), decodeErr)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, fmt.Errorf("Vyper 握手失败: SessionToken 解码失败: %w", decodeErr)
	}
	clientSessionToken := string(decodedToken)

	if clientSessionToken != string(expectedSessionToken) {
		log.Printf("Inbound: SessionToken 验证失败 (%s): 客户端 %x, 预期 %x", rawConn.RemoteAddr(), clientSessionToken, expectedSessionToken)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, errors.New("Vyper 握手失败: SessionToken 不匹配")
	}

	log.Printf("Inbound: Vyper 客户端 %s 认证成功", rawConn.RemoteAddr())

	// 4. 认证成功：发送填充帧作为确认 (900-1400字节)
	paddingLen := rand.Intn(501) + 900 // 900 到 1400 之间
	padData := make([]byte, paddingLen)
	rand.Read(padData)

	padFrame := NewPadFrame(padData)
	if _, err := WriteFrame(rawConn, padFrame); err != nil {
		log.Printf("Inbound: 发送认证成功填充帧失败 (%s): %v", rawConn.RemoteAddr(), err)
		rawConn.Close()
		return nil, fmt.Errorf("Vyper 握手失败: 无法发送认证确认帧: %w", err)
	}
	log.Printf("Inbound: 已发送认证成功填充帧，长度 %d", paddingLen)

	// 握手成功，返回一个封装了 Vyper 协议逻辑的 net.Conn
	// 服务器端主动填充，使用客户端请求的 InitialPaddingRule 对应的模式
	// 如果客户端请求 0xFF，服务器默认使用第一个模式
	var serverPaddingRule byte = 0x01 // 默认使用第一个模式
	if initFrame.InitialPaddingRule == 0xFF && len(i.paddingPatterns) > 0 {
		serverPaddingRule = 0x01 // 客户端请求服务器决定，服务器默认使用第一个
	} else if initFrame.InitialPaddingRule >= 0x01 && int(initFrame.InitialPaddingRule-1) < len(i.paddingPatterns) {
		serverPaddingRule = initFrame.InitialPaddingRule // 使用客户端指定的模式
	} else {
		// 如果客户端规则无效，或者 0x00 (无主动填充)，服务器也不主动填充
		serverPaddingRule = 0x00
	}

	return newVyperConn(rawConn, serverPaddingRule, i.paddingPatterns), nil
}

// Close 关闭入站器，停止接受新的连接。
func (i *TCPInbound) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closed = true
	if i.listener != nil {
		return i.listener.Close()
	}
	return nil
}

// Addr 返回监听器的网络地址。
func (i *TCPInbound) Addr() net.Addr {
	if i.listener != nil {
		return i.listener.Addr()
	}
	return nil
}

// handleFallback 处理认证失败后的 HTTP Fallback
func (i *TCPInbound) handleFallback(conn net.Conn, fallbackAddr string) {
	log.Printf("Inbound: 触发 Fallback 到 %s", fallbackAddr)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Inbound: 读取 Fallback HTTP 请求失败 (%s): %v", conn.RemoteAddr(), err)
		i.sendHTTPError(conn, http.StatusBadRequest, "Invalid HTTP Request")
		return
	}

	fallbackURL, err := url.Parse(fallbackAddr)
	if err != nil {
		log.Printf("Inbound: 解析 Fallback URL 失败 (%s): %v", conn.RemoteAddr(), err)
		i.sendHTTPError(conn, http.StatusInternalServerError, "Server Fallback Misconfiguration")
		return
	}

	req.RequestURI = ""
	req.URL.Host = fallbackURL.Host
	req.URL.Scheme = fallbackURL.Scheme
	req.URL.Opaque = fallbackURL.Opaque

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Inbound: 转发 Fallback 请求到 %s 失败 (%s): %v", fallbackAddr, conn.RemoteAddr(), err)
		i.sendHTTPError(conn, http.StatusBadGateway, "Fallback Target Unreachable")
		return
	}
	defer resp.Body.Close()

	err = resp.Write(conn)
	if err != nil {
		log.Printf("Inbound: 写入 Fallback 响应到客户端失败 (%s): %v", conn.RemoteAddr(), err)
	}

	log.Printf("Inbound: 已处理 Fallback 请求，关闭连接 %s", conn.RemoteAddr())
}

// sendHTTPError 向连接发送一个简单的 HTTP 错误响应
func (i *TCPInbound) sendHTTPError(w io.Writer, statusCode int, message string) {
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
		log.Printf("Inbound: 发送 HTTP 错误响应失败: %v", err)
	}
}
