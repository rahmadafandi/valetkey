// Command valetkey serves the valetkey MCP gateway.
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
	_ "time/tzdata" // TZ works without the image shipping zoneinfo

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/rahmadafandi/valetkey/internal/auth"
	"github.com/rahmadafandi/valetkey/internal/config"
	"github.com/rahmadafandi/valetkey/internal/creds"
	"github.com/rahmadafandi/valetkey/internal/integrations/argocd"
	"github.com/rahmadafandi/valetkey/internal/integrations/bitbucket"
	"github.com/rahmadafandi/valetkey/internal/integrations/jenkins"
	"github.com/rahmadafandi/valetkey/internal/integrations/loki"
	"github.com/rahmadafandi/valetkey/internal/integrations/metrics"
	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/vault"
	"github.com/rahmadafandi/valetkey/internal/web"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	h, err := buildHandler(cfg, st, google.Endpoint, log)
	if err != nil {
		return err
	}
	go cleanup(ctx, st, log)

	srv := &http.Server{Addr: cfg.Addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Info("listening", "addr", cfg.Addr, "public_url", cfg.PublicURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func cleanup(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := st.DeleteExpired(ctx); err != nil {
				log.Warn("cleanup failed", "err", err)
			}
		}
	}
}

func buildHandler(cfg config.Config, st *store.Store, googleEndpoint oauth2.Endpoint, log *slog.Logger) (http.Handler, error) {
	v, err := vault.New(cfg.VaultKey)
	if err != nil {
		return nil, err
	}
	cr := creds.Store{DB: st, Vault: v, Log: log}
	ints, err := integrations(cfg)
	if err != nil {
		return nil, err
	}
	catalog, err := web.LoadCatalog(cfg.CatalogFile)
	if err != nil {
		return nil, err
	}

	as := &auth.Server{
		Store:  st,
		Signer: auth.NewSigner(cfg.SessionKey),
		Google: &oauth2.Config{
			ClientID: cfg.GoogleClientID, ClientSecret: cfg.GoogleSecret, Endpoint: googleEndpoint,
			RedirectURL: cfg.PublicURL + "/oauth/google/callback", Scopes: []string{"openid", "email"},
		},
		PublicURL: cfg.PublicURL, AllowedDomains: cfg.AllowedDomains,
		AccessTTL: cfg.AccessTTL, RefreshTTL: cfg.RefreshTTL, Log: log,
	}
	mux := http.NewServeMux()
	as.Routes(mux)
	mux.Handle("/mcp", tools.HTTPHandler(ints, cr.Load, cfg.PublicURL, log, as.Verify, as.ResourceMetadataURL()))
	(&web.Web{Auth: as, Creds: cr, Integrations: ints, Catalog: catalog, PublicURL: cfg.PublicURL, Log: log}).Routes(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux, nil
}

// integrations builds the upstream integrations whose <SYSTEM>_URL is set.
func integrations(cfg config.Config) ([]tools.Integration, error) {
	var ints []tools.Integration
	if u, ok := cfg.Upstreams["jenkins"]; ok {
		j, err := jenkins.New(u.URL, u.Insecure)
		if err != nil {
			return nil, err
		}
		ints = append(ints, j)
	}
	if u, ok := cfg.Upstreams["argocd"]; ok {
		ints = append(ints, argocd.New(u.URL, u.Insecure))
	}
	if u, ok := cfg.Upstreams["loki"]; ok {
		ints = append(ints, loki.New(u.URL, u.Insecure))
	}
	if u, ok := cfg.Upstreams["metrics"]; ok {
		ints = append(ints, metrics.New(u.URL, u.Insecure))
	}
	if u, ok := cfg.Upstreams["bitbucket"]; ok {
		ints = append(ints, bitbucket.New(u.URL, u.Insecure))
	}
	return ints, nil
}
