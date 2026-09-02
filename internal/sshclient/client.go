package sshclient

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Host key checks always finish before authentication material is sent.
func open(ctx context.Context, c Connection, auth []ssh.AuthMethod, check ssh.HostKeyCallback) (*ssh.Client, error) {
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", c.Address())
	if err != nil {
		return nil, ErrCredential
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	deadline := time.Now().Add(15 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = raw.SetDeadline(deadline)
	conn, chans, requests, err := ssh.NewClientConn(raw, c.Address(), &ssh.ClientConfig{User: c.Username, Auth: auth, HostKeyCallback: check, ClientVersion: "SSH-2.0-CyberStrikeAI"})
	if err != nil {
		stop()
		raw.Close()
		return nil, err
	}
	if !stop() {
		conn.Close()
		return nil, ctx.Err()
	}
	_ = raw.SetDeadline(time.Time{})
	return ssh.NewClient(conn, chans, requests), nil
}

func Probe(ctx context.Context, c Connection) (string, error) {
	var fingerprint string
	observed := errors.New("host key observed; authentication deliberately skipped")
	_, err := open(ctx, c, nil, func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(key)
		return observed
	})
	if errors.Is(err, observed) && fingerprint != "" {
		return fingerprint, nil
	}
	return "", ErrCredential
}

func Dial(ctx context.Context, c Connection, credential Credential) (*ssh.Client, error) {
	if !ValidFingerprint(c.Fingerprint) {
		return nil, ErrTrust
	}
	var auth ssh.AuthMethod
	if c.AuthType == "password" {
		auth = ssh.Password(credential.Password)
	} else {
		key, err := signer(credential)
		if err != nil {
			return nil, ErrCredential
		}
		auth = ssh.PublicKeys(key)
	}
	client, err := open(ctx, c, []ssh.AuthMethod{auth}, func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if subtle.ConstantTimeCompare([]byte(ssh.FingerprintSHA256(key)), []byte(c.Fingerprint)) != 1 {
			return ErrTrust
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrTrust) {
			return nil, ErrTrust
		}
		return nil, ErrCredential
	}
	return client, nil
}
