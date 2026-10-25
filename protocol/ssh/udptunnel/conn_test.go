// Derived from github.com/idefav/ssh-tunnel/core/udptunnel; retained UDP-over-SSH v1 wire protocol.
package udptunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestFrameBoundaries(t *testing.T) {
	var wire bytes.Buffer
	for _, size := range []int{0, 1, 16385, 32769, MaxPayload} {
		want := bytes.Repeat([]byte{byte(size)}, size)
		if err := WriteFrame(&wire, want); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []int{0, 1, 16385, 32769, MaxPayload} {
		got, err := ReadFrame(&wire)
		if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{byte(size)}, size)) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	if err := WriteFrame(&wire, make([]byte, MaxPayload+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxPayload+1)
	if _, err := ReadFrame(bytes.NewReader(header[:])); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

func TestReadTimeoutPreservesPartialFrameAndEmptyMessage(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewConn(a, func() { a.Close() }, "example:123")
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	first := make(chan struct{})
	resume := make(chan struct{})
	go func() {
		b.Write([]byte{0, 0})
		close(first)
		<-resume
		b.Write([]byte{0, 3, 'a', 'b', 'c', 0, 0, 0, 0})
	}()
	<-first
	p := make([]byte, 16)
	if _, err := c.Read(p); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	close(resume)
	if n, err := c.Read(p); err != nil || string(p[:n]) != "abc" {
		t.Fatalf("%q %v", p[:n], err)
	}
	if n, err := c.Read(p); err != nil || n != 0 {
		t.Fatalf("empty %d %v", n, err)
	}
}

func TestConcurrentWritesDoNotInterleave(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewConn(a, func() { a.Close() }, "example:123")
	defer c.Close()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := bytes.Repeat([]byte{byte(i)}, 33000)
			if _, err := c.Write(p); err != nil {
				t.Error(err)
			}
		}(i)
	}
	seen := make(map[byte]bool)
	for i := 0; i < 16; i++ {
		p, err := ReadFrame(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 33000 || !bytes.Equal(p, bytes.Repeat(p[:1], len(p))) {
			t.Fatal("interleaved")
		}
		seen[p[0]] = true
	}
	wg.Wait()
	if len(seen) != 16 {
		t.Fatal("lost messages")
	}
}

func TestWriteTimeoutClosesPartialStream(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewConn(a, func() { a.Close() }, "example:123")
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Write([]byte("blocked")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("partial stream stayed open")
	}
}

func TestCapabilityIsCachedAndFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		ok    bool
		reply []byte
		want  error
	}{{false, nil, ErrUnsupported}, {true, []byte{1}, ErrDisabled}, {true, []byte{2}, ErrUpstream}, {true, nil, ErrProtocol}} {
		calls := 0
		d := Dialer{Query: func() (bool, []byte, error) { calls++; return tc.ok, tc.reply, nil }, Open: func([]byte) (io.ReadWriteCloser, error) { t.Fatal("unexpected open"); return nil, nil }, Abort: func() {}}
		for i := 0; i < 2; i++ {
			if _, err := d.Dial(context.Background(), "example.com:53"); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		}
		if calls != 1 {
			t.Fatal(calls)
		}
	}
}
