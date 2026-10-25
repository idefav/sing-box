package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/ssh/udptunnel"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/ssh"
)

func udpFixture(t *testing.T, status int) (*Outbound, *ssh.Client) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) != "fixture" {
			return nil, errors.New("authentication rejected")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	go func() {
		raw, e := listener.Accept()
		if e != nil {
			return
		}
		server, channels, requests, e := ssh.NewServerConn(raw, serverConfig)
		if e != nil {
			raw.Close()
			return
		}
		defer server.Close()
		go func() {
			for r := range requests {
				if r.Type == udptunnel.CapabilityRequest {
					if status < 0 {
						r.Reply(false, nil)
					} else {
						r.Reply(true, []byte{byte(status)})
					}
				} else {
					r.Reply(false, nil)
				}
			}
		}()
		for incoming := range channels {
			if incoming.ChannelType() == udptunnel.ChannelType {
				var target struct {
					Host string
					Port uint32
				}
				if ssh.Unmarshal(incoming.ExtraData(), &target) != nil || target.Host == "deny.example" {
					incoming.Reject(ssh.Prohibited, "ACL denied")
					continue
				}
				channel, reqs, e := incoming.Accept()
				if e != nil {
					continue
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					defer channel.Close()
					for {
						p, e := udptunnel.ReadFrame(channel)
						if e != nil {
							return
						}
						if e = udptunnel.WriteFrame(channel, p); e != nil {
							return
						}
					}
				}()
			} else if incoming.ChannelType() == "direct-tcpip" {
				channel, reqs, e := incoming.Accept()
				if e != nil {
					continue
				}
				go ssh.DiscardRequests(reqs)
				go func() { defer channel.Close(); io.Copy(channel, channel) }()
			} else {
				incoming.Reject(ssh.UnknownChannelType, "unsupported")
			}
		}
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.Password("fixture")}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	out := &Outbound{client: client, udpForwarding: true, udpSlots: make(chan struct{}, 64), udpDialer: newUDPDialer(client)}
	return out, client
}

func TestUDPEchoAndPacketSemantics(t *testing.T) {
	out, _ := udpFixture(t, 0)
	for _, target := range []string{"127.0.0.1:1234", "[::1]:1234", "remote.example:1234"} {
		destination := M.ParseSocksaddr(target)
		conn, err := out.ListenPacket(context.Background(), destination)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{0, 1, 1200, 16385, 32769, 65507} {
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			want := bytes.Repeat([]byte{byte(size)}, size)
			if n, e := conn.WriteTo(want, destination); e != nil || n != size {
				t.Fatal(n, e)
			}
			b := make([]byte, 65535)
			n, from, e := conn.ReadFrom(b)
			if e != nil || !bytes.Equal(b[:n], want) || from.String() != target {
				t.Fatal(size, n, from, e)
			}
		}
		if _, err = conn.WriteTo([]byte("wrong"), M.ParseSocksaddr("other.example:1234")); err == nil {
			t.Fatal("destination mismatch accepted")
		}
		conn.Close()
	}
	if len(out.udpSlots) != 0 || out.streams != 0 {
		t.Fatal("accounting leaked", len(out.udpSlots), out.streams)
	}
}

func TestUDPPolicyDoesNotBreakTCP(t *testing.T) {
	for status, want := range map[int]error{-1: udptunnel.ErrUnsupported, 1: udptunnel.ErrDisabled, 2: udptunnel.ErrUpstream} {
		out, client := udpFixture(t, status)
		tcp, err := client.Dial("tcp", "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = out.ListenPacket(context.Background(), M.ParseSocksaddr("127.0.0.1:1234")); !errors.Is(err, want) {
			t.Fatal(status, err)
		}
		if _, err = tcp.Write([]byte("tcp-alive")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 9)
		if _, err = io.ReadFull(tcp, b); err != nil || string(b) != "tcp-alive" {
			t.Fatal(err)
		}
		tcp.Close()
		if len(out.udpSlots) != 0 || out.streams != 0 {
			t.Fatal("failed open leaked accounting")
		}
	}
}

func TestDomainSurvivesSingPacketAdapter(t *testing.T) {
	out, _ := udpFixture(t, 0)
	destination := M.ParseSocksaddr("remote.example:3478")
	conn, err := out.ListenPacket(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	packets := bufio.NewPacketConn(conn)
	b := buf.NewPacket()
	b.Write([]byte("domain-payload"))
	if err = packets.WritePacket(b, destination); err != nil {
		t.Fatal(err)
	}
	reply := buf.NewPacket()
	defer reply.Release()
	from, err := packets.ReadPacket(reply)
	if err != nil || from != destination || string(reply.Bytes()) != "domain-payload" {
		t.Fatal(from, err)
	}
}

func TestUDPDisabledAndChannelLimit(t *testing.T) {
	out, _ := udpFixture(t, 0)
	out.udpForwarding = false
	if _, err := out.ListenPacket(context.Background(), M.ParseSocksaddr("127.0.0.1:1234")); !errors.Is(err, udptunnel.ErrUnsupported) {
		t.Fatal(err)
	}
	out.udpForwarding = true
	if _, err := out.ListenPacket(context.Background(), M.ParseSocksaddr("deny.example:1234")); err == nil {
		t.Fatal("ACL bypass")
	}
	var all []net.PacketConn
	for i := 0; i < 64; i++ {
		c, err := out.ListenPacket(context.Background(), M.ParseSocksaddr("127.0.0.1:1234"))
		if err != nil {
			t.Fatal(i, err)
		}
		all = append(all, c)
	}
	if _, err := out.ListenPacket(context.Background(), M.ParseSocksaddr("127.0.0.1:1234")); err == nil {
		t.Fatal("channel limit bypass")
	}
	for _, c := range all {
		c.Close()
	}
	if len(out.udpSlots) != 0 || out.streams != 0 {
		t.Fatal("channel cleanup leaked accounting")
	}
}
