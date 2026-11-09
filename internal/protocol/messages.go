// Package protocol implements the mylocalon Tunnel Protocol v1 wire format
// (docs/PROTOCOL.md). It is pure: no I/O, no networking.
package protocol

// Version is the only protocol version this Gateway speaks.
const Version = 1

// Subprotocol is the Sec-WebSocket-Protocol value for v1.
const Subprotocol = "mylocalon.v1"

// Message types (PROTOCOL §5).
const (
	TypeHello        = "HELLO"
	TypeWelcome      = "WELCOME"
	TypePing         = "PING"
	TypePong         = "PONG"
	TypeHTTPRequest  = "HTTP_REQUEST"
	TypeHTTPResponse = "HTTP_RESPONSE"
	TypeError        = "ERROR"
	TypeGoAway       = "GOAWAY"
	TypeClose        = "CLOSE"
)

// Error codes (PROTOCOL §9.3).
const (
	CodeVersionUnsupported  = "VERSION_UNSUPPORTED"
	CodeAuthFailed          = "AUTH_FAILED"
	CodeAuthRevoked         = "AUTH_REVOKED"
	CodeSubdomainForbidden  = "SUBDOMAIN_FORBIDDEN"
	CodeSubdomainTaken      = "SUBDOMAIN_TAKEN"
	CodeTunnelLimit         = "TUNNEL_LIMIT"
	CodeRateLimited         = "RATE_LIMITED"
	CodeResumeExpired       = "RESUME_EXPIRED"
	CodeProtocolError       = "PROTOCOL_ERROR"
	CodeUpstreamUnreachable = "UPSTREAM_UNREACHABLE"
	CodeUpstreamTimeout     = "UPSTREAM_TIMEOUT"
	CodeBodyTooLarge        = "BODY_TOO_LARGE"
	// CodeInternal is used for GOAWAY on gateway-side faults (e.g. Redis down).
	CodeInternal = "INTERNAL"
	// CodeShutdown is used for GOAWAY during a gateway restart.
	CodeShutdown = "SHUTDOWN"
)

// Header is one header as a [name, value] pair. Pairs (not a map) preserve
// order and duplicates such as multiple Set-Cookie headers.
type Header [2]string

// Message is implemented by every concrete message type.
type Message interface {
	MessageType() string
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os,omitempty"`
}

type TunnelRequest struct {
	Subdomain  string `json:"subdomain,omitempty"`
	TargetHint string `json:"targetHint,omitempty"`
}

type ResumeRequest struct {
	TunnelID    string `json:"tunnelId"`
	ResumeToken string `json:"resumeToken"`
}

type Hello struct {
	Type     string         `json:"type"`
	Protocol int            `json:"protocol"`
	Token    string         `json:"token"`
	Client   ClientInfo     `json:"client"`
	Tunnel   *TunnelRequest `json:"tunnel,omitempty"`
	Resume   *ResumeRequest `json:"resume,omitempty"`
}

type Heartbeat struct {
	IntervalMs int64 `json:"intervalMs"`
	TimeoutMs  int64 `json:"timeoutMs"`
}

type Limits struct {
	MaxBodyBytes int64 `json:"maxBodyBytes"`
}

type Welcome struct {
	Type        string    `json:"type"`
	TunnelID    string    `json:"tunnelId"`
	Subdomain   string    `json:"subdomain"`
	URL         string    `json:"url"`
	ResumeToken string    `json:"resumeToken"`
	Heartbeat   Heartbeat `json:"heartbeat"`
	Limits      Limits    `json:"limits"`
}

type Ping struct {
	Type string `json:"type"`
	TS   int64  `json:"ts"`
}

type Pong struct {
	Type string `json:"type"`
	TS   int64  `json:"ts"`
}

type HTTPRequest struct {
	Type          string   `json:"type"`
	ReqID         string   `json:"reqId"`
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	Headers       []Header `json:"headers"`
	BodyB64       string   `json:"bodyB64"`
	BodyTruncated bool     `json:"bodyTruncated"`
	RemoteIP      string   `json:"remoteIp"`
	ReceivedAt    int64    `json:"receivedAt"`
}

type HTTPResponse struct {
	Type       string   `json:"type"`
	ReqID      string   `json:"reqId"`
	Status     int      `json:"status"`
	Headers    []Header `json:"headers"`
	BodyB64    string   `json:"bodyB64"`
	DurationMs int64    `json:"durationMs"`
}

type Error struct {
	Type      string `json:"type"`
	ReqID     string `json:"reqId,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable,omitempty"`
}

type GoAway struct {
	Type      string `json:"type"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Reconnect bool   `json:"reconnect"`
}

type Close struct {
	Type     string `json:"type"`
	TunnelID string `json:"tunnelId,omitempty"`
}

func (Hello) MessageType() string        { return TypeHello }
func (Welcome) MessageType() string      { return TypeWelcome }
func (Ping) MessageType() string         { return TypePing }
func (Pong) MessageType() string         { return TypePong }
func (HTTPRequest) MessageType() string  { return TypeHTTPRequest }
func (HTTPResponse) MessageType() string { return TypeHTTPResponse }
func (Error) MessageType() string        { return TypeError }
func (GoAway) MessageType() string       { return TypeGoAway }
func (Close) MessageType() string        { return TypeClose }
