package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/ssh/udptunnel"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/ssh"
)

func newUDPDialer(client *ssh.Client) *udptunnel.Dialer {
	return &udptunnel.Dialer{
		Query: func() (bool, []byte, error) { return client.SendRequest(udptunnel.CapabilityRequest, true, nil) },
		Open: func(payload []byte) (io.ReadWriteCloser, error) {
			ch, requests, err := client.OpenChannel(udptunnel.ChannelType, payload)
			if err == nil {
				go ssh.DiscardRequests(requests)
			}
			return ch, err
		},
		Abort: func() { client.Close() },
	}
}

func (s *Outbound) dialUDP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if !s.udpForwarding {
		return nil, udptunnel.ErrUnsupported
	}
	select {
	case s.udpSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, errors.New("E_UDP_CHANNEL_LIMIT")
	}
	releaseSlot := func() { <-s.udpSlots }
	client, err := s.connect(ctx)
	if err != nil {
		releaseSlot()
		return nil, err
	}
	s.clientAccess.Lock()
	dialer := s.udpDialer
	if s.client != client {
		dialer = nil
	}
	s.clientAccess.Unlock()
	if dialer == nil {
		s.releaseStream(client, false)
		releaseSlot()
		return nil, net.ErrClosed
	}
	conn, err := dialer.Dial(ctx, destination.String())
	if err != nil {
		s.releaseStream(client, false)
		releaseSlot()
		return nil, err
	}
	keep := adapter.KeepSessionFromContext(ctx)
	wrapped := &udpConn{Conn: conn, release: func() { s.releaseStream(client, keep); releaseSlot() }}
	// Conn idle expiry / peer closure releases accounting even without a caller Close.
	go func() { <-conn.(*udptunnel.Conn).Done(); wrapped.releaseOnce() }()
	return wrapped, nil
}

type udpConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *udpConn) releaseOnce() { c.once.Do(c.release) }
func (c *udpConn) Close() error { err := c.Conn.Close(); c.releaseOnce(); return err }

// One routed UDP flow has one fixed destination. Domain targets stay remote;
// do not resolve them locally or silently send packets to a different target.
type udpPacketConn struct {
	net.Conn
	destination M.Socksaddr
}

var _ N.NetPacketConn = (*udpPacketConn)(nil)

func (c *udpPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.destination, err
}
func (c *udpPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr != nil && M.SocksaddrFromNet(addr) != c.destination {
		return 0, errors.New("E_UDP_DESTINATION_MISMATCH")
	}
	return c.Write(b)
}

// Implement sing's packet API directly: its generic net.PacketConn wrapper
// converts domain Socksaddr values to UDPAddr, which discards the hostname.
func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, err := c.Read(buffer.FreeBytes())
	buffer.Truncate(n)
	return c.destination, err
}
func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if destination.Unwrap() != c.destination.Unwrap() {
		return errors.New("E_UDP_DESTINATION_MISMATCH")
	}
	_, err := c.Write(buffer.Bytes())
	return err
}
