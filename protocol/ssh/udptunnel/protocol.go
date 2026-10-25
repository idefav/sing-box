// Derived from github.com/idefav/ssh-tunnel/core/udptunnel; retained UDP-over-SSH v1 wire protocol.
// Package udptunnel carries datagrams over an authenticated SSH byte stream.
// It depends only on the standard library; SSH ownership stays with the caller.
package udptunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ChannelType = "direct-udpip-v1@idefav.github.io"
const CapabilityRequest = "udp-forwarding-v1@idefav.github.io"
const MaxPayload = 65507
const IdleTimeout = 60 * time.Second

var (
	ErrUnsupported = errors.New("E_UDP_PROXY_UNSUPPORTED")
	ErrDisabled    = errors.New("E_UDP_FORWARDING_DISABLED")
	ErrUpstream    = errors.New("E_UDP_UPSTREAM_UNSUPPORTED")
	ErrProtocol    = errors.New("E_UDP_PROTOCOL")
	ErrTooLarge    = errors.New("E_UDP_MESSAGE_TOO_LARGE")
)

// Dialer belongs to exactly one authenticated SSH connection. Abort must close
// that connection and unblock outstanding SSH calls; no local fallback exists.
type Dialer struct {
	Query  func() (bool, []byte, error)
	Open   func([]byte) (io.ReadWriteCloser, error)
	Abort  func()
	once   sync.Once
	capErr error
}

func (d *Dialer) Dial(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	n, pe := strconv.ParseUint(port, 10, 16)
	if err != nil || pe != nil || n == 0 || host == "" || len(host) > 255 || strings.IndexByte(host, 0) >= 0 {
		return nil, ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// SSH cannot cancel a pending global request or channel open. Retire the
	// owning transport on cancellation, as the mobile TCP transport already does.
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { d.Abort(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	d.once.Do(func() {
		ok, reply, e := d.Query()
		d.capErr = e
		if e != nil {
			return
		}
		if !ok {
			d.capErr = ErrUnsupported
			return
		}
		if len(reply) != 1 {
			d.capErr = ErrProtocol
			return
		}
		switch reply[0] {
		case 0:
		case 1:
			d.capErr = ErrDisabled
		case 2:
			d.capErr = ErrUpstream
		default:
			d.capErr = ErrProtocol
		}
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if d.capErr != nil {
		return nil, d.capErr
	}
	// Open payload is an SSH string target host followed by uint32 target port.
	payload := make([]byte, 8+len(host))
	binary.BigEndian.PutUint32(payload, uint32(len(host)))
	copy(payload[4:], host)
	binary.BigEndian.PutUint32(payload[4+len(host):], uint32(n))
	stream, err := d.Open(payload)
	if ctx.Err() != nil {
		if stream != nil {
			stream.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return NewConn(stream, d.Abort, target), nil
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > MaxPayload {
		return nil, ErrTooLarge
	}
	p := make([]byte, int(n))
	_, err := io.ReadFull(r, p)
	return p, err
}

func WriteFrame(w io.Writer, p []byte) error {
	if len(p) > MaxPayload {
		return ErrTooLarge
	}
	b := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(b, uint32(len(p)))
	copy(b[4:], p)
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
