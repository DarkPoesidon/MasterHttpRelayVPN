//go:build !android && !linux

package mastervpncore

import (
	"errors"
	"net"
)

type Protector interface {
	Protect(socketFD int32) bool
}

type TunBridge struct{}

func SetProtector(_ Protector) {}

func NewTunBridge(_ int32, _ Config) (*TunBridge, error) {
	return nil, errors.New("TUN bridge build is only available on Android/Linux targets")
}

func (b *TunBridge) Close() {}

func newProtectedNetDialer() net.Dialer {
	return net.Dialer{}
}
