package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mylocalon/mylocalon-gateway/internal/protocol"
)

// ErrSessionClosed is returned when forwarding to a tunnel whose socket is gone.
var ErrSessionClosed = errors.New("tunnel session closed")

const (
	writeWait          = 10 * time.Second
	maxControlMsgBytes = 64 << 10 // PROTOCOL §13
	sendBuffer         = 256
)

type result struct {
	resp *protocol.HTTPResponse
	err  *protocol.Error
}

// Session is one live tunnel socket. Per-request state (pending responses by
// reqId) lives here, in the process that owns the socket (ARCHITECTURE §3).
type Session struct {
	ID        string
	Subdomain string
	UserID    string

	hub         *Hub
	conn        *websocket.Conn
	log         *slog.Logger
	connectedAt time.Time

	send    chan []byte
	writeMu sync.Mutex // single writer to the socket at any moment
	done    chan struct{}

	mu      sync.Mutex
	pending map[string]chan result
	closed  bool

	closeOnce   sync.Once
	intentional atomic.Bool // CLOSE/GOAWAY/protocol error: no resume grace
	replaced    atomic.Bool // superseded by a resumed session
	reason      atomic.Value
}

func newSession(h *Hub, conn *websocket.Conn, id, sub, user string, log *slog.Logger) *Session {
	return &Session{
		ID: id, Subdomain: sub, UserID: user,
		hub: h, conn: conn, log: log, connectedAt: h.clock.Now(),
		send:    make(chan []byte, sendBuffer),
		done:    make(chan struct{}),
		pending: map[string]chan result{},
	}
}

// Forward sends an HTTP_REQUEST over the tunnel and waits for the matching
// HTTP_RESPONSE or ERROR. ctx bounds the wait (the public request timeout).
func (s *Session) Forward(ctx context.Context, req *protocol.HTTPRequest) (*protocol.HTTPResponse, *protocol.Error, error) {
	ch := make(chan result, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, ErrSessionClosed
	}
	s.pending[req.ReqID] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, req.ReqID)
		s.mu.Unlock()
	}()

	data, err := protocol.Encode(req)
	if err != nil {
		return nil, nil, err
	}
	select {
	case s.send <- data:
	case <-s.done:
		return nil, nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	select {
	case r := <-ch:
		return r.resp, r.err, nil
	case <-s.done:
		return nil, nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (s *Session) deliver(reqID string, r result) {
	s.mu.Lock()
	ch := s.pending[reqID]
	s.mu.Unlock()
	if ch == nil {
		// The public request already timed out (PROTOCOL §8.2): drop.
		s.log.Debug("late_response_dropped", "reqId", reqID)
		return
	}
	select {
	case ch <- r:
	default:
	}
}

// writeNow writes one message synchronously, serialized with the write pump.
func (s *Session) writeNow(m protocol.Message) error {
	data, err := protocol.Encode(m)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return s.conn.WriteMessage(websocket.TextMessage, data)
}

// terminate closes the socket once. goaway (optional) is sent first.
// intentional=true means the tunnel is CLOSED; false means DISCONNECTED with a
// resume grace window.
func (s *Session) terminate(goaway *protocol.GoAway, intentional bool, reason string) {
	s.closeOnce.Do(func() {
		s.intentional.Store(intentional)
		s.reason.Store(reason)
		if goaway != nil {
			_ = s.writeNow(goaway)
		}
		_ = s.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason), time.Now().Add(time.Second))
		_ = s.conn.Close()
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		close(s.done)
	})
}

func (s *Session) closeReason() string {
	if v, ok := s.reason.Load().(string); ok {
		return v
	}
	return ""
}

// writePump is the only goroutine that drains s.send; it also drives the
// Gateway-initiated heartbeat (PROTOCOL §7) and refreshes runtime-state TTLs.
func (s *Session) writePump() {
	ticker := time.NewTicker(s.hub.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case data := <-s.send:
			s.writeMu.Lock()
			_ = s.conn.SetWriteDeadline(time.Now().Add(writeWait))
			err := s.conn.WriteMessage(websocket.TextMessage, data)
			s.writeMu.Unlock()
			if err != nil {
				s.terminate(nil, false, "write_error")
				return
			}
		case <-ticker.C:
			if err := s.writeNow(&protocol.Ping{TS: s.hub.clock.Now().UnixMilli()}); err != nil {
				s.terminate(nil, false, "write_error")
				return
			}
			s.hub.refresh(s)
		case <-s.done:
			return
		}
	}
}

// readPump runs on the connection's goroutine until the socket dies. Any
// message from the client counts as liveness (PROTOCOL §7).
func (s *Session) readPump() {
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(s.hub.cfg.HeartbeatTimeout))
		mt, data, err := s.conn.ReadMessage()
		if err != nil {
			reason := "socket_closed"
			var ne interface{ Timeout() bool }
			if errors.As(err, &ne) && ne.Timeout() {
				reason = "heartbeat_timeout"
			}
			s.terminate(nil, false, reason)
			return
		}
		if mt != websocket.TextMessage {
			s.protocolError("binary frames are not allowed in v1")
			return
		}
		msg, err := protocol.Decode(data)
		if err != nil {
			s.protocolError(err.Error())
			return
		}
		if _, isResp := msg.(*protocol.HTTPResponse); !isResp && len(data) > maxControlMsgBytes {
			s.protocolError("control message exceeds 64KiB")
			return
		}
		switch m := msg.(type) {
		case *protocol.Pong:
			// liveness only
		case *protocol.Ping:
			_ = s.writeNow(&protocol.Pong{TS: m.TS})
		case *protocol.HTTPResponse:
			s.handleResponse(m)
		case *protocol.Error:
			if m.ReqID != "" {
				s.deliver(m.ReqID, result{err: m})
			} else {
				s.log.Warn("client_error", "code", m.Code, "message", m.Message)
			}
		case *protocol.Close:
			s.terminate(nil, true, "client_close")
			return
		default:
			s.protocolError("unexpected message " + msg.MessageType())
			return
		}
	}
}

func (s *Session) handleResponse(m *protocol.HTTPResponse) {
	// base64 inflates by 4/3; check the decoded size cheaply first.
	if int64(len(m.BodyB64))*3/4 > s.hub.cfg.MaxBodyBytes {
		s.deliver(m.ReqID, result{err: &protocol.Error{
			ReqID: m.ReqID, Code: protocol.CodeBodyTooLarge, Message: "response body exceeds limit",
		}})
		return
	}
	s.deliver(m.ReqID, result{resp: m})
}

func (s *Session) protocolError(msg string) {
	s.log.Warn("protocol_error", "message", msg)
	_ = s.writeNow(&protocol.Error{Code: protocol.CodeProtocolError, Message: msg})
	s.terminate(nil, true, "protocol_error")
}
