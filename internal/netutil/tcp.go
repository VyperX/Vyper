package netutil

import (
	"net"
	"time"
)

// ListenTCP 启动TCP监听器
func ListenTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// DialTCP 拨号TCP
func DialTCP(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}