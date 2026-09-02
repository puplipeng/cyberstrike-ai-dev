package sshclient

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

var (
	ErrInvalid    = errors.New("invalid SSH connection")
	ErrConflict   = errors.New("connection changed; reload before saving")
	ErrTrust      = errors.New("host key is untrusted or changed")
	ErrCredential = errors.New("SSH authentication or connection failed")
	ErrBusy       = errors.New("SSH connection limit reached")
)

type Credential struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type Input struct {
	Name       string      `json:"name"`
	Host       string      `json:"host"`
	Port       int         `json:"port"`
	Username   string      `json:"username"`
	AuthType   string      `json:"auth_type"`
	Credential *Credential `json:"credential,omitempty"`
	Revision   int64       `json:"revision"`
}

type Connection struct {
	ID          string `json:"id"`
	Owner       string `json:"owner_id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	AuthType    string `json:"auth_type"`
	Fingerprint string `json:"fingerprint"`
	Revision    int64  `json:"revision"`
	Secret      []byte `json:"-"`
}

func (c Connection) Address() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

var domainRE = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
var fingerprintRE = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

func ValidFingerprint(value string) bool { return fingerprintRE.MatchString(value) }
func cleanText(value string, max int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= max && !strings.ContainsFunc(value, unicode.IsControl)
}
func (in *Input) Validate() error {
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	if !cleanText(in.Name, 200) || !cleanText(in.Username, 128) || len(in.Host) > 253 || in.Port < 1 || in.Port > 65535 {
		return ErrInvalid
	}
	if ip := net.ParseIP(in.Host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return ErrInvalid
		}
		in.Host = ip.String()
	} else if !domainRE.MatchString(in.Host) || strings.Contains(in.Host, "..") {
		return ErrInvalid
	}
	if in.AuthType != "password" && in.AuthType != "key" {
		return ErrInvalid
	}
	if in.Credential != nil {
		c := in.Credential
		if len(c.Password) > 16384 || len(c.PrivateKey) > 65536 || len(c.Passphrase) > 16384 {
			return ErrInvalid
		}
		if in.AuthType == "password" {
			if c.Password == "" {
				return ErrInvalid
			}
			c.PrivateKey = ""
			c.Passphrase = ""
		} else {
			if _, err := signer(*c); err != nil {
				return ErrInvalid
			}
			c.Password = ""
		}
	}
	return nil
}
func signer(c Credential) (ssh.Signer, error) {
	if c.Passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(c.PrivateKey), []byte(c.Passphrase))
	}
	return ssh.ParsePrivateKey([]byte(c.PrivateKey))
}
