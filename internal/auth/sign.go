package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// Sign creates an EdDSA JWT. The Gateway binary never calls this; it exists
// for tests and the cmd/devtoken helper that stands in for the Platform in
// local development.
func Sign(priv ed25519.PrivateKey, kid string, claims any) (string, error) {
	hdr := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(priv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
