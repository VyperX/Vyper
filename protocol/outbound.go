package protocol

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Outbound 抽象出口，所有出站流量（TCP/UDP封装后）都用这个
type Outbound interface {
	Connect(network, address string) (net.Conn, error)
	Close() error
}

type TCPOutbound struct {
	timeout time.Duration
	mu      sync.Mutex
	closed  bool
}

func NewTCPOutbound(timeout time.Duration) *TCPOutbound {
	return &TCPOutbound{timeout: timeout}
}

func (o *TCPOutbound) Connect(network, address string) (net.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, errors.New("outbound closed")
	}
	return net.DialTimeout(network, address, o.timeout)
}

func (o *TCPOutbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	return nil
}
