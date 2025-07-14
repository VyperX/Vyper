package netutil

import (
	"net"
	"time"
)

// ListenUDP 启动UDP监听器
func ListenUDP(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", udpAddr)
}

// DialUDP 拨号UDP
func DialUDP(addr string, timeout time.Duration) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	return conn, nil
}