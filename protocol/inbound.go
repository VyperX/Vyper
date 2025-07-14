package protocol

import (
	"errors"
	"net"
	"sync"
	"io"
)

// Inbound 抽象入口，所有入站流量（TCP/UDP封装后）都用这个
type Inbound interface {
	Listen() error
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

type TCPInbound struct {
	addr     string
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

func NewTCPInbound(addr string) *TCPInbound {
	return &TCPInbound{addr: addr}
}

func (i *TCPInbound) Listen() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return errors.New("inbound closed")
	}
	ln, err := net.Listen("tcp", i.addr)
	if err != nil {
		return err
	}
	i.listener = ln
	return nil
}

func (i *TCPInbound) Accept() (net.Conn, error) {
	if i.listener == nil {
		return nil, errors.New("inbound not listening")
	}
	return i.listener.Accept()
}

func (i *TCPInbound) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closed = true
	if i.listener != nil {
		return i.listener.Close()
	}
	return nil
}

func (i *TCPInbound) Addr() net.Addr {
	if i.listener != nil {
		return i.listener.Addr()
	}
	return nil
}
