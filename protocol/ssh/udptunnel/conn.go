// Derived from github.com/idefav/ssh-tunnel/core/udptunnel; retained UDP-over-SSH v1 wire protocol.
package udptunnel

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type address string

func (a address) Network() string { return "udp" }
func (a address) String() string  { return string(a) }

type writeRequest struct {
	payload []byte
	result  chan error
}

// Conn implements net.Conn with datagram semantics: one Write is one message,
// one Read consumes one whole message, including empty messages. A short Read
// discards the remainder and returns io.ErrShortBuffer. Incoming queue overflow
// drops whole datagrams. Read timeouts never discard partially decoded frames.
type Conn struct {
	stream  io.ReadWriteCloser
	abort   func()
	target  string
	packets chan []byte
	writes  chan writeRequest
	done    chan struct{}
	workers sync.WaitGroup
	once    sync.Once
	mu      sync.Mutex
	err     error
	rd, wd  time.Time
	wake    chan struct{}
	idle    *time.Timer
}

func NewConn(stream io.ReadWriteCloser, abort func(), target string) *Conn {
	c := &Conn{stream: stream, abort: abort, target: target, packets: make(chan []byte, 4), writes: make(chan writeRequest), done: make(chan struct{}), wake: make(chan struct{})}
	c.idle = time.AfterFunc(IdleTimeout, func() { c.fail(os.ErrDeadlineExceeded) })
	c.workers.Add(2)
	go c.readLoop()
	go c.writeLoop()
	return c
}

// Done allows an owner to retire stream accounting on peer close and idle expiry.
func (c *Conn) Done() <-chan struct{} { return c.done }

func (c *Conn) touch() {
	c.mu.Lock()
	if c.err == nil {
		c.idle.Reset(IdleTimeout)
	}
	c.mu.Unlock()
}

func (c *Conn) fail(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.idle.Stop()
		close(c.done)
		c.mu.Unlock()
		// A peer that does not acknowledge channel close can leave the Go SSH
		// reader/window writer blocked. Bound cleanup by retiring its transport.
		go func() {
			finished := make(chan struct{})
			go func() { c.stream.Close(); c.workers.Wait(); close(finished) }()
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-finished:
			case <-timer.C:
				c.abort()
				<-finished
			}
		}()
	})
}

func (c *Conn) readLoop() {
	defer c.workers.Done()
	for {
		p, err := ReadFrame(c.stream)
		if err != nil {
			c.fail(err)
			return
		}
		c.touch()
		select {
		case <-c.done:
			return
		default:
		}
		select {
		case c.packets <- p:
		default: /* whole-message tail drop */
		}
	}
}

func (c *Conn) writeLoop() {
	defer c.workers.Done()
	for {
		select {
		case <-c.done:
			return
		case w := <-c.writes:
			err := WriteFrame(c.stream, w.payload)
			w.result <- err
			if err != nil {
				c.fail(err)
				return
			}
			c.touch()
		}
	}
}

func (c *Conn) deadline(write bool) (<-chan time.Time, <-chan struct{}, func()) {
	c.mu.Lock()
	t, wake := c.rd, c.wake
	if write {
		t = c.wd
	}
	c.mu.Unlock()
	if t.IsZero() {
		return nil, wake, func() {}
	}
	timer := time.NewTimer(time.Until(t))
	return timer.C, wake, func() { timer.Stop() }
}

func (c *Conn) closedError() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

func (c *Conn) expired(write bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.rd
	if write {
		d = c.wd
	}
	return !d.IsZero() && !time.Now().Before(d)
}

func (c *Conn) Read(p []byte) (int, error) {
	for {
		if c.expired(false) {
			return 0, os.ErrDeadlineExceeded
		}
		timer, wake, stop := c.deadline(false)
		select {
		case <-c.done:
			stop()
			return 0, c.closedError()
		case <-timer:
			stop()
			return 0, os.ErrDeadlineExceeded
		case <-wake:
			stop()
			continue
		case packet := <-c.packets:
			stop()
			n := copy(p, packet)
			if n < len(packet) {
				return n, io.ErrShortBuffer
			}
			return n, nil
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) > MaxPayload {
		return 0, ErrTooLarge
	}
	w := writeRequest{payload: append([]byte(nil), p...), result: make(chan error, 1)}
	queued := false
	for {
		if c.expired(true) {
			if queued {
				c.fail(os.ErrDeadlineExceeded)
			}
			return 0, os.ErrDeadlineExceeded
		}
		timer, wake, stop := c.deadline(true)
		var send chan writeRequest
		if !queued {
			send = c.writes
		}
		select {
		case <-c.done:
			stop()
			return 0, c.closedError()
		case <-timer:
			stop()
			if queued {
				c.fail(os.ErrDeadlineExceeded)
			}
			return 0, os.ErrDeadlineExceeded
		case <-wake:
			stop()
		case send <- w:
			stop()
			queued = true
		case err := <-w.result:
			stop()
			if err != nil {
				return 0, err
			}
			return len(p), nil
		}
	}
}

func (c *Conn) Close() error         { c.fail(net.ErrClosed); return nil }
func (c *Conn) LocalAddr() net.Addr  { return address("ssh-udp") }
func (c *Conn) RemoteAddr() net.Addr { return address(c.target) }
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rd, c.wd = t, t
	close(c.wake)
	c.wake = make(chan struct{})
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rd = t
	close(c.wake)
	c.wake = make(chan struct{})
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wd = t
	close(c.wake)
	c.wake = make(chan struct{})
	return nil
}
