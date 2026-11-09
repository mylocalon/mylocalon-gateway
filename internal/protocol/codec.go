package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrProtocol wraps every decode/validation failure; callers map it to
// PROTOCOL_ERROR.
var ErrProtocol = errors.New("protocol error")

func protoErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, args...))
}

// Encode serializes a message, stamping its type field.
func Encode(m Message) ([]byte, error) {
	switch v := m.(type) {
	case *Hello:
		v.Type = TypeHello
	case *Welcome:
		v.Type = TypeWelcome
	case *Ping:
		v.Type = TypePing
	case *Pong:
		v.Type = TypePong
	case *HTTPRequest:
		v.Type = TypeHTTPRequest
		if v.Headers == nil {
			v.Headers = []Header{}
		}
	case *HTTPResponse:
		v.Type = TypeHTTPResponse
		if v.Headers == nil {
			v.Headers = []Header{}
		}
	case *Error:
		v.Type = TypeError
	case *GoAway:
		v.Type = TypeGoAway
	case *Close:
		v.Type = TypeClose
	default:
		return nil, fmt.Errorf("encode: unsupported message %T", m)
	}
	return json.Marshal(m)
}

// Decode parses one JSON text frame into a concrete *Message. Unknown fields
// are ignored (PROTOCOL §3); unknown types and malformed messages return an
// error wrapping ErrProtocol.
func Decode(data []byte) (Message, error) {
	var env struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, protoErr("invalid json: %v", err)
	}
	if env.Type == "" {
		return nil, protoErr("missing type")
	}

	var m Message
	switch env.Type {
	case TypeHello:
		m = &Hello{}
	case TypeWelcome:
		m = &Welcome{}
	case TypePing:
		m = &Ping{}
	case TypePong:
		m = &Pong{}
	case TypeHTTPRequest:
		m = &HTTPRequest{}
	case TypeHTTPResponse:
		m = &HTTPResponse{}
	case TypeError:
		m = &Error{}
	case TypeGoAway:
		m = &GoAway{}
	case TypeClose:
		m = &Close{}
	default:
		return nil, protoErr("unknown type %q", env.Type)
	}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, protoErr("invalid %s: %v", env.Type, err)
	}
	if err := validate(m); err != nil {
		return nil, err
	}
	return m, nil
}

func validate(m Message) error {
	switch v := m.(type) {
	case *Hello:
		if v.Token == "" {
			return protoErr("HELLO.token required")
		}
		if v.Resume != nil && (v.Resume.TunnelID == "" || v.Resume.ResumeToken == "") {
			return protoErr("HELLO.resume requires tunnelId and resumeToken")
		}
	case *HTTPRequest:
		if v.ReqID == "" || v.Method == "" || v.Path == "" {
			return protoErr("HTTP_REQUEST requires reqId, method, path")
		}
		if _, err := DecodeBody(v.BodyB64); err != nil {
			return err
		}
	case *HTTPResponse:
		if v.ReqID == "" {
			return protoErr("HTTP_RESPONSE.reqId required")
		}
		if v.Status < 100 || v.Status > 999 {
			return protoErr("HTTP_RESPONSE.status out of range: %d", v.Status)
		}
		if _, err := DecodeBody(v.BodyB64); err != nil {
			return err
		}
	case *Error:
		if v.Code == "" {
			return protoErr("ERROR.code required")
		}
	case *GoAway:
		if v.Code == "" {
			return protoErr("GOAWAY.code required")
		}
	}
	return nil
}

// UnmarshalJSON enforces that a header is exactly a two-element string array.
func (h *Header) UnmarshalJSON(b []byte) error {
	var pair []string
	if err := json.Unmarshal(b, &pair); err != nil {
		return protoErr("header must be [name, value]: %v", err)
	}
	if len(pair) != 2 {
		return protoErr("header must have exactly 2 elements, got %d", len(pair))
	}
	h[0], h[1] = pair[0], pair[1]
	return nil
}

// EncodeBody returns standard padded base64.
func EncodeBody(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// DecodeBody parses standard padded base64; "" decodes to an empty body.
func DecodeBody(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, protoErr("invalid base64 body: %v", err)
	}
	return b, nil
}
