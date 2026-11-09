// Command gateway runs the mylocalon tunnel Gateway.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mylocalon/mylocalon-gateway/internal/auth"
	"github.com/mylocalon/mylocalon-gateway/internal/clock"
	"github.com/mylocalon/mylocalon-gateway/internal/config"
	"github.com/mylocalon/mylocalon-gateway/internal/ingress"
	"github.com/mylocalon/mylocalon-gateway/internal/logging"
	"github.com/mylocalon/mylocalon-gateway/internal/metrics"
	"github.com/mylocalon/mylocalon-gateway/internal/platform"
	"github.com/mylocalon/mylocalon-gateway/internal/ratelimit"
	"github.com/mylocalon/mylocalon-gateway/internal/server"
	"github.com/mylocalon/mylocalon-gateway/internal/store"
	"github.com/mylocalon/mylocalon-gateway/internal/tunnel"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logging.New(os.Stdout, "gateway", cfg.Env, cfg.LogLevel)
	clk := clock.Real{}

	ctx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	var static auth.StaticKeys
	if cfg.JWTPublicKeys != "" {
		if static, err = auth.LoadPublicKeys(cfg.JWTPublicKeys); err != nil {
			return err
		}
	}
	var keySource auth.KeySource = static
	if cfg.JWKSURL != "" {
		jwks := auth.NewJWKSKeys(cfg.JWKSURL, static, log)
		// The Platform may still be starting: retry briefly, then keep going —
		// unknown kids trigger a refresh at handshake time anyway.
		for i := 0; i < 15 && jwks.Refresh(ctx) != nil; i++ {
			time.Sleep(2 * time.Second)
		}
		if jwks.Len() == 0 && len(static) == 0 {
			log.Error("no JWT verification keys yet; tunnels will be refused until the JWKS is reachable", "url", cfg.JWKSURL)
		}
		go jwks.Run(ctx, 5*time.Minute)
		keySource = jwks
	}
	verifier := auth.NewEd25519Verifier(keySource, cfg.JWTIssuer, cfg.JWTAudience, clk)

	var st store.Store
	if cfg.RedisURL == "" {
		log.Warn("using in-memory store: single node only, state lost on restart")
		st = store.NewMemory(clk)
	} else {
		r, err := store.NewRedis(cfg.RedisURL)
		if err != nil {
			return err
		}
		defer r.Close()
		st = r
	}

	m := metrics.New()
	hub := tunnel.NewHub(cfg, st, verifier, m, clk, log)
	pubDone := make(chan struct{})
	if cfg.PlatformURL != "" {
		pc := platform.NewClient(cfg.PlatformURL, cfg.InternalToken)
		reserved := platform.NewReserved(pc, log)
		publisher := platform.NewPublisher(pc, log)
		go reserved.Run(ctx, 30*time.Second)
		go func() { publisher.Run(ctx); close(pubDone) }()
		hub.WithReserved(reserved).WithLifecycle(publisher)
	} else {
		close(pubDone)
		log.Warn("ML_PLATFORM_URL not set: no reserved-name sync or dashboard events")
	}
	in := ingress.New(cfg, server.TunnelsAdapter{Hub: hub}, ratelimit.New(st, log), m, clk, log).
		WithFilter(ingress.NewBasicFilter(cfg.BaseDomain, cfg.BlockedSubdomains))

	public := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.Public(cfg, hub, in, clk),
		MaxHeaderBytes:    cfg.MaxHeaderBytes, // → 431 at the edge
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	admin := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           server.Admin(st, m, clk),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errc := make(chan error, 2)
	go func() { errc <- serve(public) }()
	go func() { errc <- serve(admin) }()
	log.Info("gateway_started", "listen", cfg.ListenAddr, "admin", cfg.AdminAddr,
		"baseDomain", cfg.BaseDomain, "version", server.Version, "node", cfg.NodeID)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case s := <-sig:
		log.Info("shutdown_started", "signal", s.String())
	}

	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hub.Shutdown(sctx)
	_ = public.Shutdown(sctx)
	_ = admin.Shutdown(sctx)
	stopBackground() // final flush of lifecycle events
	select {
	case <-pubDone:
	case <-sctx.Done():
	}
	log.Info("shutdown_complete")
	return nil
}

func serve(s *http.Server) error {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
