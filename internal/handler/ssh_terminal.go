package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/sshclient"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

func sshOrigin(r *http.Request) bool {
	u, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && strings.EqualFold(u.Host, r.Host)
}

const (
	sshCookie            = "ssh_terminal_ticket"
	sshTerminalTicketTTL = 5 * time.Minute
)

func (h *SSHHandler) Ticket(c *gin.Context) {
	item, _, ok := h.connection(c, "webshell:write")
	if !ok {
		return
	}
	if c.GetHeader("Origin") != "" && !sshOrigin(c.Request) {
		c.JSON(403, gin.H{"error": "跨站请求被拒绝"})
		return
	}
	if !sshclient.ValidFingerprint(item.Fingerprint) {
		h.fail(c, sshclient.ErrTrust)
		return
	}
	token := c.GetString(security.ContextAuthTokenKey)
	if token == "" {
		c.JSON(401, gin.H{"error": "请重新登录"})
		return
	}
	ticket := uuid.NewString() + uuid.NewString()
	h.mu.Lock()
	now := time.Now()
	for key, t := range h.tickets {
		if t.expires.Before(now) || (t.token == token && t.connection == item.ID) {
			delete(h.tickets, key)
		}
	}
	if h.closed || len(h.tickets) >= 1000 {
		h.mu.Unlock()
		h.fail(c, sshclient.ErrBusy)
		return
	}
	h.tickets[ticket] = sshTicket{item.ID, token, now.Add(sshTerminalTicketTTL)}
	h.mu.Unlock()
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(sshCookie, ticket, int(sshTerminalTicketTTL/time.Second), "/api/ssh/connections/"+item.ID+"/terminal", "", c.Request.TLS != nil, true)
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"ok": true, "expires_in": int(sshTerminalTicketTTL / time.Second)})
}

// Runs before AuthMiddleware only on the SSH WebSocket route. No auth token in URLs.
func (h *SSHHandler) AuthenticateSocket(c *gin.Context) {
	if !sshOrigin(c.Request) || c.Request.URL.RawQuery != "" {
		c.AbortWithStatusJSON(403, gin.H{"error": "无效的终端来源"})
		return
	}
	value, _ := c.Cookie(sshCookie)
	h.mu.Lock()
	ticket, ok := h.tickets[value]
	delete(h.tickets, value)
	h.mu.Unlock()
	if !ok || ticket.connection != c.Param("id") || time.Now().After(ticket.expires) {
		c.AbortWithStatusJSON(401, gin.H{"error": "终端凭证已过期，请重新连接"})
		return
	}
	c.Request.Header.Set("Authorization", "Bearer "+ticket.token)
	c.Next()
}

type sshSocketWriter struct {
	mu     sync.Mutex
	socket *websocket.Conn
}

func (w *sshSocketWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.socket.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := w.socket.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return 0, err
	}
	return len(data), nil
}
func (h *SSHHandler) Terminal(c *gin.Context) {
	item, s, ok := h.connection(c, "webshell:write")
	if !ok {
		return
	}
	if !sshOrigin(c.Request) {
		c.JSON(403, gin.H{"error": "无效的终端来源"})
		return
	}
	ctx, done, ok := h.begin(c, item, s, 30*time.Minute)
	if !ok {
		return
	}
	defer done()
	client, closeClient, err := h.dial(ctx, item)
	if err != nil {
		h.record(c, "terminal_open", item.ID, err, nil)
		h.fail(c, err)
		return
	}
	defer closeClient()
	setupTimeout := time.AfterFunc(15*time.Second, func() { client.Close() })
	defer setupTimeout.Stop()
	session, err := client.NewSession()
	if err != nil {
		h.fail(c, sshclient.ErrCredential)
		return
	}
	defer session.Close()
	if err = session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		h.fail(c, sshclient.ErrCredential)
		return
	}
	input, err := session.StdinPipe()
	if err != nil {
		h.fail(c, err)
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		h.fail(c, err)
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		h.fail(c, err)
		return
	}
	if err = session.Shell(); err != nil {
		h.fail(c, sshclient.ErrCredential)
		return
	}
	upgrader := websocket.Upgrader{CheckOrigin: sshOrigin, ReadBufferSize: 4096, WriteBufferSize: 4096, HandshakeTimeout: 10 * time.Second}
	if !setupTimeout.Stop() {
		h.fail(c, context.DeadlineExceeded)
		return
	}
	socket, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer socket.Close()
	stop := context.AfterFunc(ctx, func() { socket.Close() })
	defer stop()
	h.record(c, "terminal_open", item.ID, nil, nil)
	defer h.record(c, "terminal_close", item.ID, nil, nil)
	writer := &sshSocketWriter{socket: socket}
	var copies sync.WaitGroup
	copies.Add(2)
	for _, reader := range []io.Reader{stdout, stderr} {
		go func(r io.Reader) {
			defer copies.Done()
			if _, err := io.Copy(writer, r); err != nil {
				socket.Close()
				client.Close()
			}
		}(reader)
	}
	defer func() { client.Close(); socket.Close(); copies.Wait() }()
	go func() { copies.Wait(); socket.Close() }()
	// Auth expiry/revocation and connection edits close live channels within 15 seconds.
	token := c.GetString(security.ContextAuthTokenKey)
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				fresh, valid := security.Session{}, false
				if h.auth != nil {
					fresh, valid = h.auth.ValidateToken(token)
				}
				if !valid || !fresh.Permissions["webshell:read"] || !fresh.Permissions["webshell:write"] || (item.Owner != fresh.UserID && !sshAll(fresh, "webshell:write")) || h.store.Check(watchCtx, item) != nil {
					client.Close()
					socket.Close()
					return
				}
				_ = socket.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			}
		}
	}()
	socket.SetReadLimit(64 << 10)
	_ = socket.SetReadDeadline(time.Now().Add(60 * time.Second))
	socket.SetPongHandler(func(string) error { return socket.SetReadDeadline(time.Now().Add(60 * time.Second)) })
	for {
		kind, data, err := socket.ReadMessage()
		if err != nil {
			return
		}
		if kind == websocket.BinaryMessage {
			if _, err = input.Write(data); err != nil {
				return
			}
		} else if kind == websocket.TextMessage {
			var resize struct {
				Type string `json:"type"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if json.Unmarshal(data, &resize) != nil || resize.Type != "resize" || resize.Cols < 1 || resize.Cols > 500 || resize.Rows < 1 || resize.Rows > 300 {
				return
			}
			if session.WindowChange(resize.Rows, resize.Cols) != nil {
				return
			}
		}
	}
}
