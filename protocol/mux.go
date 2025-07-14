package protocol

import (
	"io"
	"net"
	"sync"

	v2mux "github.com/v2fly/v2ray-core/v5/common/mux"
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
)

// Session 表示一个 mux.cool 多路复用session（主连接）
type Session interface {
	OpenStream(dest v2net.Destination) (Stream, error)
	AcceptStream() (Stream, v2net.Destination, error)
	Close() error
}

// v2Session 管理一个主连接和所有子流
type v2Session struct {
	conn    net.Conn
	manager *v2mux.SessionManager
	lock    sync.Mutex
	closed  bool
}

func NewSession(conn net.Conn) Session {
	return &v2Session{
		conn:    conn,
		manager: v2mux.NewSessionManager(),
	}
}

// OpenStream 打开一个新的子流（TCP/UDP都可以）
func (s *v2Session) OpenStream(dest v2net.Destination) (Stream, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.closed {
		return nil, io.ErrClosedPipe
	}
	ses := s.manager.Allocate()
	if ses == nil {
		return nil, io.ErrClosedPipe
	}
	return newV2Stream(s.conn, ses, dest), nil
}

// AcceptStream 阻塞接收新子流
func (s *v2Session) AcceptStream() (Stream, v2net.Destination, error) {
	// 生产环境应有专门协程解帧/分发。这里只是演示。
	return nil, v2net.Destination{}, io.EOF
}

func (s *v2Session) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.closed = true
	return s.conn.Close()
}
