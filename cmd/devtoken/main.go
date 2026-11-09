// Command devtoken stands in for the Platform during local development:
// it generates an Ed25519 keypair and signs Gateway JWTs. Never deploy it.
//
//	go run ./cmd/devtoken -gen-keys -out keys
//	go run ./cmd/devtoken -key keys/ed25519.key -sub usr_dev -subdomains myapp
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/auth"
	"github.com/mylocalon/mylocalon-gateway/internal/httpx"
)

func main() {
	genKeys := flag.Bool("gen-keys", false, "generate ed25519.key / ed25519.pub into -out")
	out := flag.String("out", "keys", "output dir for -gen-keys")
	keyPath := flag.String("key", "keys/ed25519.key", "private key PEM")
	sub := flag.String("sub", "usr_dev", "subject (user id)")
	ttl := flag.Duration("ttl", time.Hour, "token lifetime")
	subs := flag.String("subdomains", "", "comma-separated reserved subdomains the user owns")
	maxTunnels := flag.Int("max-tunnels", 0, "optional per-user tunnel limit claim")
	kid := flag.String("kid", "default", "key id header")
	flag.Parse()

	var err error
	if *genKeys {
		err = generate(*out)
	} else {
		err = sign(*keyPath, *kid, *sub, *ttl, *subs, *maxTunnels)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "devtoken:", err)
		os.Exit(1)
	}
}

func generate(dir string) error {
	priv := filepath.Join(dir, "ed25519.key")
	if _, err := os.Stat(priv); err == nil {
		return fmt.Errorf("%s already exists; delete it to regenerate", priv)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	pkix, _ := x509.MarshalPKIXPublicKey(pub)
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", priv, "and", filepath.Join(dir, "ed25519.pub"))
	return nil
}

func sign(path, kid, sub string, ttl time.Duration, subs string, maxTunnels int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return errors.New("no PEM block in key file")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return errors.New("not an Ed25519 private key")
	}
	now := time.Now()
	claims := map[string]any{
		"sub": sub, "iss": "mylocalon-platform", "aud": "mylocalon-gateway",
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": httpx.NewID("jti_", 8),
	}
	limits := map[string]any{}
	if subs != "" {
		limits["subdomains"] = strings.Split(subs, ",")
	}
	if maxTunnels > 0 {
		limits["maxTunnels"] = maxTunnels
	}
	if len(limits) > 0 {
		claims["limits"] = limits
	}
	tok, err := auth.Sign(priv, kid, claims)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}
