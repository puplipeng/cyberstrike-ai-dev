// Package sshtest provides an inert loopback SSH/SFTP fixture. It executes no OS commands.
package sshtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	closed                                                   bool
	Address, Password, PrivateKey, EncryptedKey, Fingerprint string
	AuthCalls                                                atomic.Int32
	Resizes                                                  atomic.Int32
	Active                                                   atomic.Int32
	listener                                                 net.Listener
	config                                                   *ssh.ServerConfig
	handlers                                                 sftp.Handlers
	mu                                                       sync.Mutex
	connections                                              map[net.Conn]bool
	wg                                                       sync.WaitGroup
}

type Option func(*Server)

// Directory generates metadata only, with counters for bounded-enumeration tests.
type Directory struct {
	Count, NameLength int
	Emitted, Closed   atomic.Int64
}

func (d *Directory) Filelist(*sftp.Request) (sftp.ListerAt, error) { return d, nil }
func (d *Directory) ListAt(entries []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(d.Count) {
		return 0, io.EOF
	}
	n := min(len(entries), d.Count-int(offset))
	for i := 0; i < n; i++ {
		entries[i] = directoryInfo{strings.Repeat("x", d.NameLength) + fmt.Sprintf("item-%05d.txt", int(offset)+i)}
	}
	d.Emitted.Add(int64(n))
	if int(offset)+n == d.Count {
		return n, io.EOF
	}
	return n, nil
}
func (d *Directory) Close() error { d.Closed.Add(1); return nil }

type directoryInfo struct{ name string }

func (f directoryInfo) Name() string     { return f.name }
func (directoryInfo) Size() int64        { return 0 }
func (directoryInfo) Mode() os.FileMode  { return 0600 }
func (directoryInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (directoryInfo) IsDir() bool        { return false }
func (directoryInfo) Sys() any           { return nil }

func WithFileLister(lister sftp.FileLister) Option {
	return func(s *Server) {
		if lister != nil {
			s.handlers.FileList = lister
		}
	}
}

func Start(t testing.TB, options ...Option) *Server {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(private, "fixture", []byte("fixture-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Password: "fixture-password", PrivateKey: string(pem.EncodeToMemory(block)), EncryptedKey: string(pem.EncodeToMemory(encrypted)), Fingerprint: ssh.FingerprintSHA256(hostKey.PublicKey()), handlers: sftp.InMemHandler(), connections: map[net.Conn]bool{}}
	for _, option := range options {
		option(s)
	}
	s.config = &ssh.ServerConfig{MaxAuthTries: 2,
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			s.AuthCalls.Add(1)
			if c.User() == "fixture" && string(password) == s.Password {
				return nil, nil
			}
			return nil, errors.New("fixture authentication rejected")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.AuthCalls.Add(1)
			if c.User() == "fixture" && bytes.Equal(key.Marshal(), userKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("fixture key rejected")
		}}
	s.config.AddHostKey(hostKey)
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Address = s.listener.Addr().String()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			raw, err := s.listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				raw.Close()
				return
			}
			s.connections[raw] = true
			s.mu.Unlock()
			s.wg.Add(1)
			go s.serve(raw)
		}
	}()
	t.Cleanup(func() {
		s.listener.Close()
		s.mu.Lock()
		s.closed = true
		for c := range s.connections {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}
func (s *Server) serve(raw net.Conn) {
	defer s.wg.Done()
	defer func() { raw.Close(); s.mu.Lock(); delete(s.connections, raw); s.mu.Unlock() }()
	conn, channels, requests, err := ssh.NewServerConn(raw, s.config)
	if err != nil {
		return
	}
	defer conn.Close()
	s.Active.Add(1)
	defer s.Active.Add(-1)
	go ssh.DiscardRequests(requests)
	var sessions sync.WaitGroup
	defer sessions.Wait()
	for next := range channels {
		if next.ChannelType() != "session" {
			next.Reject(ssh.UnknownChannelType, "fixture only")
			continue
		}
		channel, reqs, err := next.Accept()
		if err != nil {
			continue
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer channel.Close()
			started := false
			for r := range reqs {
				switch r.Type {
				case "pty-req":
					r.Reply(true, nil)
				case "window-change":
					s.Resizes.Add(1)
					r.Reply(true, nil)
				case "shell":
					if started {
						r.Reply(false, nil)
						continue
					}
					started = true
					r.Reply(true, nil)
					go func() { channel.Write([]byte("fixture-ready\r\n")); io.Copy(channel, channel); channel.Close() }()
				case "subsystem":
					var sub struct{ Name string }
					ssh.Unmarshal(r.Payload, &sub)
					if started || sub.Name != "sftp" {
						r.Reply(false, nil)
						continue
					}
					started = true
					r.Reply(true, nil)
					go func() { server := sftp.NewRequestServer(channel, s.handlers); defer server.Close(); server.Serve() }()
				default:
					r.Reply(false, nil)
				}
			}
		}()
	}
}
