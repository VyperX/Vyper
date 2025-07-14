package api

import (
	"net"
)

// Handler 定义流量处理接口，可灵活扩展业务逻辑
type Handler interface {
	// OnConnect 在流建立时调用
	OnConnect(conn net.Conn) error
	// OnData 接收到数据时调用
	OnData(conn net.Conn, data []byte) error
	// OnClose 在连接关闭时调用
	OnClose(conn net.Conn) error
}

// UDPHandler 定义UDP场景下的处理接口
type UDPHandler interface {
	// OnPacket 处理收到的UDP包
	OnPacket(addr net.Addr, data []byte) ([]byte, error)
}

// DefaultHandler 示例实现，实际业务可自定义
type DefaultHandler struct{}

func (h *DefaultHandler) OnConnect(conn net.Conn) error { return nil }
func (h *DefaultHandler) OnData(conn net.Conn, data []byte) error { return nil }
func (h *DefaultHandler) OnClose(conn net.Conn) error { return nil }

type DefaultUDPHandler struct{}

func (h *DefaultUDPHandler) OnPacket(addr net.Addr, data []byte) ([]byte, error) { return nil, nil }