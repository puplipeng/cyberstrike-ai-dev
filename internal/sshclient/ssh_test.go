package sshclient

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/testutil/sshtest"
	"cyberstrike-ai/internal/testutil/testpostgres"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func fixtureConnection(t *testing.T, f *sshtest.Server) Connection {
	t.Helper()
	host, port, err := net.SplitHostPort(f.Address)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return Connection{Host: host, Port: p, Username: "fixture", AuthType: "password", Fingerprint: f.Fingerprint}
}
func TestProbeAndHostKeyValidationBeforeCredentials(t *testing.T) {
	f := sshtest.Start(t)
	c := fixtureConnection(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fingerprint, err := Probe(ctx, c)
	if err != nil || fingerprint != f.Fingerprint || f.AuthCalls.Load() != 0 {
		t.Fatal("probe sent authentication or wrong key", err)
	}
	c.Fingerprint = "SHA256:" + strings.Repeat("a", 43)
	if _, err = Dial(ctx, c, Credential{Password: f.Password}); !errors.Is(err, ErrTrust) || f.AuthCalls.Load() != 0 {
		t.Fatal("changed host key accepted or leaked credentials", err)
	}
	c.Fingerprint = f.Fingerprint
	for _, method := range []string{"password", "key"} {
		c.AuthType = method
		client, err := Dial(ctx, c, Credential{Password: f.Password, PrivateKey: f.EncryptedKey, Passphrase: "fixture-passphrase"})
		if err != nil {
			t.Fatal(method, err)
		}
		client.Close()
	}
	c.AuthType = "password"
	if _, err = Dial(ctx, c, Credential{Password: "wrong"}); !errors.Is(err, ErrCredential) {
		t.Fatal("wrong credentials accepted", err)
	}
}
func TestDialHandshakeCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		var b [1024]byte
		for {
			if _, err = raw.Read(b[:]); err != nil {
				return
			}
		}
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Probe(ctx, Connection{Host: host, Port: p, Username: "fixture"})
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("handshake cancellation not bounded", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("raw connection leaked")
	}
}
func TestInputValidation(t *testing.T) {
	base := Input{Name: "test", Host: "127.0.0.1", Port: 22, Username: "fixture", AuthType: "password", Credential: &Credential{Password: "  keep spaces  "}}
	if err := base.Validate(); err != nil || base.Credential.Password != "  keep spaces  " {
		t.Fatal("password altered", err)
	}
	for _, host := range []string{"http://example.test", "host\nx", "-oProxyCommand=x", "0.0.0.0", "169.254.169.254", "a..b", "x:22", "[::1]"} {
		in := base
		in.Host = host
		if in.Validate() == nil {
			t.Fatal("invalid host accepted", host)
		}
	}
	for _, host := range []string{"localhost", "example.test", "::1", "192.168.0.1"} {
		in := base
		in.Host = host
		if err := in.Validate(); err != nil {
			t.Fatal(host, err)
		}
	}
	in := base
	in.AuthType = "key"
	in.Credential = &Credential{PrivateKey: "not a key"}
	if in.Validate() == nil {
		t.Fatal("invalid key accepted")
	}
}
func TestEncryptedStoreOwnershipRevisionAndKeyPersistence(t *testing.T) {
	db, err := sql.Open("pgx", testpostgres.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	key := filepath.Join(t.TempDir(), "vault", "master.key")
	s, err := NewStore(ctx, db, key)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Name: "server", Host: "127.0.0.1", Port: 22, Username: "fixture", AuthType: "password", Credential: &Credential{Password: "secret-fixture-unique"}}
	c, err := s.Save(ctx, "", "owner", false, in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(c.Secret, []byte(in.Credential.Password)) {
		t.Fatal("plaintext stored")
	}
	raw, _ := json.Marshal(c)
	if bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte(in.Credential.Password)) {
		t.Fatal("credential serialized")
	}
	list, err := s.List(ctx, "other", false)
	if err != nil || len(list) != 0 {
		t.Fatal("ownership bypass", err)
	}
	if _, err = s.Get(ctx, c.ID, "other", false); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("hidden connection accessible", err)
	}
	in.Revision = c.Revision
	in.Credential = nil
	if _, err = s.Save(ctx, c.ID, "other", false, in); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("ownership update bypass", err)
	}
	if err = s.Trust(ctx, c, "SHA256:"+strings.Repeat("a", 43)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Save(ctx, c.ID, "owner", false, in); !errors.Is(err, ErrConflict) {
		t.Fatal("stale save accepted", err)
	}
	c, _ = s.Get(ctx, c.ID, "owner", false)
	in.Revision = c.Revision
	in.Host = "localhost"
	c, err = s.Save(ctx, c.ID, "owner", false, in)
	if err != nil || c.Fingerprint != "" {
		t.Fatal("host edit retained trust", err)
	}
	again, err := NewStore(ctx, db, key)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := again.Credential(c)
	if err != nil || credential.Password != "secret-fixture-unique" {
		t.Fatal("persisted key or omitted credential lost", err)
	}
	swapped := c
	swapped.ID = "other"
	if _, err = again.Credential(swapped); err == nil {
		t.Fatal("ciphertext copied between records")
	}
	if err = os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err = NewStore(ctx, db, key); err == nil {
		t.Fatal("lost key silently regenerated")
	}
	if _, err = os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing key recreated")
	}
}

func TestReadDirBoundedEntriesAndMetadata(t *testing.T) {
	for _, tc := range []struct {
		count, nameLength int
		truncated         bool
	}{{0, 0, false}, {3, 0, false}, {1000, 0, false}, {1001, 0, true}, {2500, 0, true}, {1000, 900, true}} {
		t.Run(fmt.Sprintf("%d_names_%d_bytes", tc.count, tc.nameLength), func(t *testing.T) {
			directory := &sshtest.Directory{Count: tc.count, NameLength: tc.nameLength}
			fixture := sshtest.Start(t, sshtest.WithFileLister(directory))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := Dial(ctx, fixtureConnection(t, fixture), Credential{Password: fixture.Password})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			stop := context.AfterFunc(ctx, func() { client.Close() })
			defer stop()
			items, truncated, err := ReadDirBounded(ctx, client, ".")
			if err != nil || truncated != tc.truncated {
				t.Fatalf("truncated=%v want=%v error=%v", truncated, tc.truncated, err)
			}
			if len(items) > MaxDirectoryEntries || (tc.count > 0 && len(items) == 0) {
				t.Fatal("invalid result count", len(items))
			}
			if tc.nameLength == 0 && len(items) != min(tc.count, MaxDirectoryEntries) {
				t.Fatal("missing directory entries", len(items))
			}
			if tc.nameLength > 0 && len(items) >= tc.count {
				t.Fatal("metadata byte budget did not stop enumeration")
			}
			if directory.Emitted.Load() > 1100 {
				t.Fatal("read the entire directory", directory.Emitted.Load())
			}
		})
	}
}

func TestDirectoryReaderBoundsPacketsAndBytes(t *testing.T) {
	t.Run("oversized packet rejected before payload allocation", func(t *testing.T) {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], ^uint32(0))
		r := &directoryReader{source: bytes.NewReader(header[:])}
		if _, err := io.ReadAll(r); !errors.Is(err, errDirectoryLimit) || !r.limited.Load() {
			t.Fatal("oversized packet was not bounded", err)
		}
	})
	t.Run("aggregate budget also stops empty name responses", func(t *testing.T) {
		packet := make([]byte, (32<<10)+4)
		binary.BigEndian.PutUint32(packet[:4], uint32(len(packet)-4))
		packet[4] = sftpNamePacket
		r := &directoryReader{source: bytes.NewReader(bytes.Repeat(packet, 40))}
		got, err := io.ReadAll(r)
		if !errors.Is(err, errDirectoryLimit) || len(got) > maxDirectoryBytes {
			t.Fatal("aggregate metadata limit missing", len(got), err)
		}
	})
	t.Run("truncated packet remains a protocol error", func(t *testing.T) {
		data := []byte{0, 0, 0, 9, sftpNamePacket, 0}
		r := &directoryReader{source: bytes.NewReader(data)}
		if _, err := io.ReadAll(r); !errors.Is(err, io.ErrUnexpectedEOF) || r.limited.Load() {
			t.Fatal("malformed packet was hidden as truncation", err)
		}
	})
}
