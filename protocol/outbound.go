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
	// crypto/x509 和 os 不需要在此处导入，因为它们在同一个包的 frame.go 中已导入并使用
	// 并且此文件将依赖于 frame.go 和 mux.go 中定义的通用函数和类型。
)

// =============================================================================
// Vyper 协议连接封装 (vyperConn) 及其填充逻辑。
// 这些结构和函数在此文件中定义，并在此文件和 inbound.go 中重复，
// 以确保在不创建新的通用文件的情况下，每个文件都能独立编译并包含完整的 Vyper 协议逻辑。
// =============================================================================

// vyperConn 封装了底层的 net.Conn，并处理 Vyper 协议的帧读写和填充逻辑。
// 它实现了 net.Conn 接口，使得上层应用可以直接使用它，而无需关心 Vyper 协议的细节。
type vyperConn struct {
	net.Conn // 嵌入底层连接，实现大部分 net.Conn 接口方法

	reader *bufio.Reader // 带缓冲的读取器，用于高效读取底层连接

	// 写入相关
	writeMutex   sync.Mutex    // 保护写入操作，确保并发写入的安全性
	paddingState *paddingState // 填充状态，用于管理出站流量的混淆填充

	// 读取相关
	readBuffer *bytes.Buffer // 用于存储已解封装的 Vyper DATA_FRAME 内容，提供给上层读取
	readMutex  sync.Mutex    // 保护读取操作，确保并发读取的安全性
}

// paddingState 结构体用于管理当前连接的填充状态。
// 它包含了动态突发协商和随机交错所需的所有参数。
type paddingState struct {
	allPatterns          [][]int   // 所有可用的填充模式，每个模式是长度范围的序列
	currentPatternIndex  int       // 当前选定的填充模式的索引
	currentStepInPattern int       // 当前模式中，下一个要发送的 PAD_FRAME 的步骤索引
	lastPaddingTime      time.Time // 上次发送填充帧的时间，可用于未来实现基于时间的填充间隔
}

// newPaddingState 初始化填充状态。
// initialRule: Vyper Initialization Frame 中协商的初始填充规则。
// allPatterns: 客户端或服务器配置的所有“Padding Burst Patterns”。
func newPaddingState(initialRule byte, allPatterns [][]int) *paddingState {
	ps := &paddingState{
		allPatterns:     allPatterns,
		lastPaddingTime: time.Now(),
	}

	// 根据 InitialPaddingRule 选择或确定当前填充模式。
	if initialRule >= 0x01 && int(initialRule-1) < len(allPatterns) {
		// 0x01 到 0xFE：客户端指定一个具体的模式索引。
		ps.currentPatternIndex = int(initialRule - 1)
	} else if initialRule == 0xFF && len(allPatterns) > 0 {
		// 0xFF：客户端请求服务器决定。在此实现中，我们默认使用第一个模式。
		ps.currentPatternIndex = 0
	} else {
		// 0x00 (无主动填充) 或无效索引：表示不进行主动填充。
		ps.currentPatternIndex = -1
	}
	return ps
}

// generatePaddingFrame 根据当前填充状态生成一个 PAD_FRAME。
// 返回 nil 表示当前不应生成填充帧。
// 详细填充逻辑：
// 1. **检查是否启用了主动填充：** 如果 `currentPatternIndex` 为 -1 或 `allPatterns` 为空，则表示没有主动填充，直接返回 `nil`。
// 2. **选择当前填充模式：** 根据 `currentPatternIndex` 从 `allPatterns` 中选择当前使用的“Padding Burst Pattern”。
// 3. **处理空模式：** 如果选定的模式为空，也返回 `nil`。
// 4. **循环模式步骤：** `currentStepInPattern` 跟踪当前模式中的进度。如果已达到模式末尾，则重置为 0，实现循环填充。
// 5. **确定填充长度范围：** 从当前模式步骤中获取 `(minimum_length, maximum_length)` 范围。
// 6. **生成随机填充长度：** 在 `[minLen, maxLen]` 范围内生成一个随机整数作为 `PAD_FRAME` 的内容长度。
// 7. **生成随机填充数据：** 创建一个指定长度的字节切片，并用随机数据填充，以增加不可预测性。
// 8. **更新状态：** 递增 `currentStepInPattern` 并更新 `lastPaddingTime`。
// 9. **创建 PAD_FRAME：** 调用 `NewPadFrame` 创建并返回一个 `VyperSessionFrame` 类型的 `PAD_FRAME`。
func (ps *paddingState) generatePaddingFrame() *VyperSessionFrame {
	if ps.currentPatternIndex == -1 || len(ps.allPatterns) == 0 {
		return nil // 没有主动填充模式或没有配置模式
	}

	selectedPattern := ps.allPatterns[ps.currentPatternIndex]
	if len(selectedPattern) == 0 {
		return nil // 选定的模式为空
	}

	// 循环模式中的步骤，实现“缺乏停止计数器”的持续填充行为
	if ps.currentStepInPattern >= len(selectedPattern) {
		ps.currentStepInPattern = 0
	}

	minLen := selectedPattern[ps.currentStepInPattern][0]
	maxLen := selectedPattern[ps.currentStepInPattern][1]

	// 确保 minLen 不大于 maxLen，防止 rand.Intn 报错，提高健壮性
	if minLen > maxLen {
		minLen = maxLen // 修正不合理配置，使其至少等于 maxLen
	}

	// 生成随机长度的填充数据，实现长度的不可预测性
	paddingLen := rand.Intn(maxLen-minLen+1) + minLen
	padData := make([]byte, paddingLen)
	rand.Read(padData) // 填充随机数据，进一步混淆

	ps.currentStepInPattern++
	ps.lastPaddingTime = time.Now() // 记录上次填充时间
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
// 1. **优先读取内部缓冲区：** 首先检查 `readBuffer` 是否有已解封装的 `DATA_FRAME` 内容。如果有，直接从中读取并返回，避免不必要的底层读取。
// 2. **循环读取 Vyper 帧：** 如果 `readBuffer` 为空，则进入循环，从底层 `net.Conn` 读取一个完整的 Vyper 会话帧。
// 3. **错误处理：** 如果读取底层帧失败，检查是否为 `io.EOF`（表示连接关闭），否则返回详细错误。
// 4. **帧类型处理：**
//    - `DATA_FRAME (0x02)`: 收到实际应用数据帧。将其 `Content` 写入 `readBuffer`，然后从 `readBuffer` 读取到传入的 `b`。这是 Vyper 协议的核心数据传输。
//    - `PAD_FRAME (0x06)`: 收到混淆填充帧。其 `Content` 被完全丢弃，然后继续循环读取下一个帧。这实现了 Vyper 协议的混淆特性，接收方不处理填充数据。
//    - `CLOSE_FRAME (0x04)`: 收到关闭信号帧。表示对端已关闭其写入端。返回 `io.EOF`，通知上层应用流已结束。
//    - `ERR_FRAME (0x05)`: 收到错误帧。表示协议层发生了不可恢复的错误。返回一个包含错误信息的 `error`。
//    - `REQ_FRAME (0x01)` / `FLOW_FRAME (0x03)` 及其他未知帧：根据 Vyper 协议栈设计，`REQ_FRAME` 和 `FLOW_FRAME` 通常由 Mux.Cool 层处理。如果在 `vyperConn` 层面（即 Vyper 协议层）收到这些帧，说明协议栈可能出现了异常或误用，因此返回一个错误。
func (vc *vyperConn) Read(b []byte) (n int, err error) {
	vc.readMutex.Lock()
	defer vc.readMutex.Unlock()

	// 如果内部读取缓冲区有数据，优先读取
	if vc.readBuffer.Len() > 0 {
		return vc.readBuffer.Read(b)
	}

	// 否则，从底层连接读取 Vyper 帧并处理
	for {
		frame, err := ReadVyperSessionFrame(vc.reader) // 调用通用函数
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
			return 0, fmt.Errorf("Vyper 协议异常: 在数据流中收到 REQ_FRAME (应由 Mux.Cool 处理)")
		case 0x03: // FLOW_FRAME (此帧应由 Mux.Cool 处理，不应在 VyperConn 的 Read 中出现)
			return 0, fmt.Errorf("Vyper 协议异常: 在数据流中收到 FLOW_FRAME (应由 Mux.Cool 处理)")
		default:
			return 0, fmt.Errorf("Vyper 协议异常: 未知帧类型 %x", frame.FrameType)
		}
	}
}

// Write 将数据写入 Vyper 连接。它会将数据封装成 DATA_FRAME，并根据填充策略注入 PAD_FRAME。
// 此方法会阻塞直到数据写入完成或发生错误。
// 详细写入逻辑：
// 1. **写入 DATA_FRAME：** 将传入的原始数据 `b` 封装成一个 `DATA_FRAME`。这个帧的 `FrameType` 为 `0x02`，`Sequence` 简化为 `0`（实际应用中应维护递增序列号），`Content` 为原始数据。然后将此 `DATA_FRAME` 写入到底层连接。
// 2. **注入 PAD_FRAME (随机交错)：**
//    - 在写入 `DATA_FRAME` 之后，立即调用 `vc.paddingState.generatePaddingFrame()` 尝试生成一个 `PAD_FRAME`。
//    - 如果 `generatePaddingFrame()` 返回一个有效的 `PAD_FRAME`（表示当前填充模式要求发送填充），则将此 `PAD_FRAME` 写入到底层连接。
//    - 这种在实际数据帧之后随机插入填充帧的行为，实现了 Vyper 协议规范 Section 6.2 中描述的“随机交错”特性。
//    - 由于 `generatePaddingFrame` 的内部逻辑会循环遍历填充模式，且没有“停止”计数器，这同时实现了 Section 6.3 的“缺乏停止计数器”特性，确保填充在连接生命周期内持续活跃。
//    - 填充帧的写入失败通常被视为非致命错误，仅记录日志，不中断主数据流，以保持协议的韧性。
// 3. **返回写入长度：** 最终返回成功写入的原始数据 `b` 的长度。
func (vc *vyperConn) Write(b []byte) (n int, err error) {
	vc.writeMutex.Lock()
	defer vc.writeMutex.Unlock()

	// 1. 写入 DATA_FRAME
	dataFrame := &VyperSessionFrame{ // 使用通用结构
		FrameType: 0x02, // DATA_FRAME
		Sequence:  0,    // 简化：实际应用中应维护递增序列号
		Content:   b,
	}
	if _, err := WriteFrame(vc.Conn, dataFrame); err != nil { // 调用通用函数
		return 0, fmt.Errorf("写入 DATA_FRAME 失败: %w", err)
	}

	// 2. 注入 PAD_FRAME (随机交错)
	// 根据协议，PAD_FRAME 可以随机交错。这里选择在每次写入 DATA_FRAME 后尝试注入一个。
	// 这实现了“随机交错”和“缺乏停止计数器”的特性。
	if padFrame := vc.paddingState.generatePaddingFrame(); padFrame != nil {
		if _, err := WriteFrame(vc.Conn, padFrame); err != nil { // 调用通用函数
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

	closeFrame := &VyperSessionFrame{FrameType: 0x04, Sequence: 0, Content: []byte{}} // 使用通用结构
	if _, err := WriteFrame(vc.Conn, closeFrame); err != nil { // 调用通用函数
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
// Outbound 接口和 TCPOutbound 实现
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
	initFrame := &VyperInitializationFrame{ // 使用通用结构
		AuthBlob:           authBlob,
		InitialPaddingRule: o.initialPaddingRule,
		Reserved:           []byte{0x00, 0x00, 0x00},
		ClientInfo:         clientInfo,
	}

	// 4. 写入 Vyper Initialization Frame
	if _, err := WriteVyperInitializationFrame(rawConn, initFrame); err != nil { // 调用通用函数
		rawConn.Close()
		return nil, fmt.Errorf("写入 Vyper 初始化帧失败: %w", err)
	}
	log.Printf("Outbound: Vyper 初始化帧已发送")

	// 5. 读取服务器的认证响应 (PAD_FRAME)
	responseFrame, err := ReadVyperSessionFrame(rawConn) // 调用通用函数
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
	return newVyperConn(rawConn, o.initialPaddingRule, o.paddingPatterns), nil // 调用通用函数
}

// Close 关闭出站器，阻止新的连接。
func (o *TCPOutbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	return nil
}
