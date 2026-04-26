//go:build android || linux

package mastervpncore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const tunNICID tcpip.NICID = 1

type Protector interface {
	Protect(socketFD int32) bool
}

type TunBridge struct {
	cfg       Config
	proxyAddr string
	dnsAddr   string
	dupFD     int
	stack     *stack.Stack
	closeOnce sync.Once
}

var protectorState = struct {
	sync.RWMutex
	protector Protector
}{}

func SetProtector(protector Protector) {
	protectorState.Lock()
	defer protectorState.Unlock()
	protectorState.protector = protector
}

func NewTunBridge(tunFD int32, cfg Config) (*TunBridge, error) {
	if tunFD < 0 {
		return nil, errors.New("invalid TUN file descriptor")
	}

	dupFD, err := unix.Dup(int(tunFD))
	if err != nil {
		return nil, fmt.Errorf("dup tun fd: %w", err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{dupFD},
		MTU:            uint32(cfg.TunMTU),
		EthernetHeader: false,
	})
	if err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("create tun endpoint: %w", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	if err := tcpipToError(s.CreateNIC(tunNICID, linkEP)); err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("create nic: %w", err)
	}
	if err := tcpipToError(s.SetPromiscuousMode(tunNICID, true)); err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("set promiscuous mode: %w", err)
	}
	if err := tcpipToError(s.SetSpoofing(tunNICID, true)); err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("set spoofing: %w", err)
	}
	if err := tcpipToError(s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)); err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("enable ipv4 forwarding: %w", err)
	}
	if err := tcpipToError(s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)); err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("enable ipv6 forwarding: %w", err)
	}

	localAddr := tcpip.AddrFrom4([4]byte{10, 10, 0, 2})
	if err := tcpipToError(s.AddProtocolAddress(
		tunNICID,
		tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: localAddr.WithPrefix()},
		stack.AddressProperties{},
	)); err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("assign tun ipv4 address: %w", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: tunNICID},
		{Destination: header.IPv6EmptySubnet, NIC: tunNICID},
	})

	bridge := &TunBridge{
		cfg:       cfg,
		proxyAddr: net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort)),
		dnsAddr:   cfg.DNSResolver,
		dupFD:     dupFD,
		stack:     s,
	}

	tcpForwarder := tcp.NewForwarder(s, 0, 1024, bridge.handleTCPForward)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, bridge.handleUDPForward)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	return bridge, nil
}

func (b *TunBridge) Close() {
	b.closeOnce.Do(func() {
		if b.dupFD >= 0 {
			_ = unix.Close(b.dupFD)
			b.dupFD = -1
		}
	})
}

func (b *TunBridge) handleTCPForward(req *tcp.ForwarderRequest) {
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		req.Complete(true)
		log.Printf("mastervpncore: create tcp endpoint failed: %v", terr)
		return
	}
	req.Complete(false)

	tunConn := gonet.NewTCPConn(&wq, ep)
	targetID := req.ID()
	targetAddr := net.JoinHostPort(addressToHost(targetID.LocalAddress), strconv.Itoa(int(targetID.LocalPort)))

	go func() {
		defer tunConn.Close()

		proxyConn, err := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(context.Background(), "tcp", b.proxyAddr)
		if err != nil {
			log.Printf("mastervpncore: connect local proxy failed: %v", err)
			return
		}
		defer proxyConn.Close()

		proxyStream, err := establishProxyTunnel(proxyConn, targetAddr)
		if err != nil {
			log.Printf("mastervpncore: proxy tunnel setup failed for %s: %v", targetAddr, err)
			return
		}

		copyDone := make(chan struct{}, 2)
		go tunnelCopy(proxyStream, tunConn, copyDone)
		go tunnelCopy(tunConn, proxyStream, copyDone)
		<-copyDone
	}()
}

func (b *TunBridge) handleUDPForward(req *udp.ForwarderRequest) {
	id := req.ID()
	if id.LocalPort != 53 {
		return
	}

	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		log.Printf("mastervpncore: create udp endpoint failed: %v", terr)
		return
	}

	tunConn := gonet.NewUDPConn(b.stack, &wq, ep)

	go func() {
		defer tunConn.Close()

		dialer := newProtectedNetDialer()
		upstreamConn, err := dialer.DialContext(context.Background(), "udp", b.dnsAddr)
		if err != nil {
			log.Printf("mastervpncore: DNS dial failed (%s): %v", b.dnsAddr, err)
			return
		}
		defer upstreamConn.Close()

		reqBuf := make([]byte, 4096)
		respBuf := make([]byte, 4096)

		for {
			_ = tunConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, rerr := tunConn.Read(reqBuf)
			if rerr != nil {
				if !isTimeoutError(rerr) {
					return
				}
				continue
			}
			if n == 0 {
				continue
			}

			_ = upstreamConn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, werr := upstreamConn.Write(reqBuf[:n]); werr != nil {
				log.Printf("mastervpncore: DNS upstream write failed: %v", werr)
				return
			}

			m, uerr := upstreamConn.Read(respBuf)
			if uerr != nil {
				if !isTimeoutError(uerr) {
					log.Printf("mastervpncore: DNS upstream read failed: %v", uerr)
					return
				}
				continue
			}
			if m == 0 {
				continue
			}

			_ = tunConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, derr := tunConn.Write(respBuf[:m]); derr != nil {
				return
			}
		}
	}()

}

func establishProxyTunnel(proxyConn net.Conn, targetAddr string) (net.Conn, error) {
	request := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n",
		targetAddr,
		targetAddr,
	)
	if _, err := io.WriteString(proxyConn, request); err != nil {
		return nil, fmt.Errorf("write connect request: %w", err)
	}

	reader := bufio.NewReader(proxyConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read connect status: %w", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		return nil, fmt.Errorf("connect rejected: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read connect headers: %w", err)
		}
		if line == "\r\n" {
			break
		}
	}

	return &bufferedConn{Conn: proxyConn, reader: reader}, nil
}

func tunnelCopy(dst net.Conn, src net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	_, _ = io.Copy(dst, src)
	_ = dst.SetDeadline(time.Now())
	_ = src.SetDeadline(time.Now())
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if nerr, ok := err.(net.Error); ok {
		return nerr.Timeout()
	}
	return false
}

func addressToHost(addr tcpip.Address) string {
	if addr.Len() == net.IPv4len {
		return net.IP(addr.AsSlice()).String()
	}
	if addr.Len() == net.IPv6len {
		return net.IP(addr.AsSlice()).String()
	}
	return addr.String()
}

func tcpipToError(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v", err)
}

func newProtectedNetDialer() net.Dialer {
	return net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		ControlContext: func(_ context.Context, _, _ string, rawConn syscall.RawConn) error {
			var protectErr error
			if err := rawConn.Control(func(fd uintptr) {
				if err := protectSocketFD(int32(fd)); err != nil {
					protectErr = err
				}
			}); err != nil {
				return err
			}
			return protectErr
		},
	}
}

func protectSocketFD(fd int32) error {
	protectorState.RLock()
	protector := protectorState.protector
	protectorState.RUnlock()

	if protector == nil {
		return nil
	}
	if protector.Protect(fd) {
		return nil
	}
	return fmt.Errorf("vpn protect failed for fd=%d", fd)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
