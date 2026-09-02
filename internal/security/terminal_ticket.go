package security

import (
	"fmt"
	"github.com/google/uuid"
	"time"
)

const TerminalTicketProtocol = "csai-ticket."
const TerminalSocketPath = "/api/terminal/ws"

type terminalTicket struct {
	token   string
	expires time.Time
}

// Tickets are single-use, bounded, and tied to the still-valid login session.
// Only the short-lived ticket crosses the WebSocket subprotocol header.
func (a *AuthManager) IssueTerminalTicket(token string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	session, ok := a.sessions[token]
	if !ok || !now.Before(session.ExpiresAt) || !session.Permissions["terminal:execute"] {
		return "", fmt.Errorf("terminal authorization required")
	}
	count := 0
	for key, ticket := range a.terminalTickets {
		if !now.Before(ticket.expires) {
			delete(a.terminalTickets, key)
			continue
		}
		if ticket.token == token {
			count++
		}
	}
	if count >= 8 || len(a.terminalTickets) >= 4096 {
		return "", fmt.Errorf("too many pending terminal tickets")
	}
	ticket := uuid.NewString()
	a.terminalTickets[ticket] = terminalTicket{token, now.Add(30 * time.Second)}
	return ticket, nil
}

func (a *AuthManager) consumeTerminalTicket(ticket string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.terminalTickets[ticket]
	delete(a.terminalTickets, ticket)
	if !ok || !time.Now().Before(entry.expires) {
		return ""
	}
	return entry.token
}
