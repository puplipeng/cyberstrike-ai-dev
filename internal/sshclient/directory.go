package sshclient

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync/atomic"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	MaxDirectoryEntries = 1000
	maxDirectoryBytes   = 1 << 20
	maxDirectoryPacket  = 256 << 10
	sftpNamePacket      = 104
)

var errDirectoryLimit = errors.New("SFTP directory read budget reached")

// directoryReader bounds wire data before pkg/sftp allocates or decodes it.
// It only frames packets and counts SSH_FXP_NAME entries; pkg/sftp remains
// responsible for validating SFTP v3 responses and decoding file attributes.
// The last bounded packet can contain more entries than the display limit.
type directoryReader struct {
	source  io.Reader
	pending []byte
	bytes   uint64
	entries uint64
	limited atomic.Bool
}

func (r *directoryReader) limit() (int, error) {
	r.limited.Store(true)
	return 0, errDirectoryLimit
}

func (r *directoryReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		// Read one extra batch only when needed to distinguish exactly 1000
		// entries from a truncated directory. Never enumerate the rest.
		if r.limited.Load() || r.entries > MaxDirectoryEntries || r.bytes+4 > maxDirectoryBytes {
			return r.limit()
		}
		var header [4]byte
		if _, err := io.ReadFull(r.source, header[:]); err != nil {
			return 0, err
		}
		size := uint64(binary.BigEndian.Uint32(header[:]))
		if size == 0 {
			return 0, ErrInvalid
		}
		if size > maxDirectoryPacket || r.bytes+4+size > maxDirectoryBytes {
			return r.limit()
		}
		packet := make([]byte, 4+int(size))
		copy(packet, header[:])
		if _, err := io.ReadFull(r.source, packet[4:]); err != nil {
			return 0, err
		}
		r.bytes += uint64(len(packet))
		if packet[4] == sftpNamePacket {
			if size < 9 { // type + request ID + entry count
				return 0, io.ErrUnexpectedEOF
			}
			r.entries += uint64(binary.BigEndian.Uint32(packet[9:13]))
		}
		r.pending = packet
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// ReadDirBounded uses a dedicated subsystem so a budget stop cannot interrupt
// another transfer. The caller owns client and must cancel its SSH connection
// while opening a session, as the SSHHandler's dial helper does.
func ReadDirBounded(ctx context.Context, client *ssh.Client, remote string) ([]os.FileInfo, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, false, err
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	input, err := session.StdinPipe()
	if err != nil {
		return nil, false, err
	}
	output, err := session.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, false, err
	}
	if err := session.RequestSubsystem("sftp"); err != nil {
		return nil, false, err
	}
	drained := make(chan struct{})
	go func() { defer close(drained); _, _ = io.Copy(io.Discard, stderr) }()
	defer func() { session.Close(); <-drained }()
	reader := &directoryReader{source: output}
	files, err := sftp.NewClientPipe(reader, input)
	if err != nil {
		return nil, false, err
	}
	// Close the full SSH channel first, so Client.Close cannot wait forever
	// for a peer that ignores stdin EOF.
	defer func() { session.Close(); files.Close() }()
	entries, err := files.ReadDirContext(ctx, remote)
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	truncated := reader.limited.Load() || len(entries) > MaxDirectoryEntries
	if err != nil && !(reader.limited.Load() && len(entries) > 0) {
		return nil, false, err
	}
	if len(entries) > MaxDirectoryEntries {
		entries = entries[:MaxDirectoryEntries]
	}
	return entries, truncated, nil
}
