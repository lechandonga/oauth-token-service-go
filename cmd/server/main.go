// Command server runs the local identity & token service on 127.0.0.1.
// State is persisted under --data-dir and survives restarts.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/oauth"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (loopback only)")
	dataDir := flag.String("data-dir", "./.local-oauth-data", "directory for durable state")
	issuer := flag.String("issuer", "http://127.0.0.1:8080", "token issuer")
	audience := flag.String("audience", "local-resource-api", "token audience")
	accessTTL := flag.Duration("access-ttl", 15*time.Minute, "access token lifetime")
	refreshTTL := flag.Duration("refresh-ttl", 7*24*time.Hour, "refresh token lifetime")
	codeTTL := flag.Duration("code-ttl", 60*time.Second, "authorization code lifetime")
	leeway := flag.Duration("leeway", 30*time.Second, "clock-skew tolerance")
	grace := flag.Duration("key-grace", 24*time.Hour, "old-key grace window after rotation")
	rotateKeys := flag.Bool("rotate-keys", false, "rotate signing key at startup (old key stays valid during grace window)")
	flag.Parse()

	svc, err := oauth.New(oauth.Config{
		DataDir:        *dataDir,
		Issuer:         *issuer,
		Audience:       *audience,
		AccessTTL:      *accessTTL,
		RefreshTTL:     *refreshTTL,
		CodeTTL:        *codeTTL,
		Leeway:         *leeway,
		KeyGraceWindow: *grace,
	})
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}
	if *rotateKeys {
		if err := svc.RotateKeys(); err != nil {
			log.Fatalf("key rotation failed: %v", err)
		}
		log.Printf("signing key rotated; active kid=%s", svc.CurrentKeyID())
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("local oauth service listening on http://%s (data=%s)", *addr, *dataDir)
	log.Printf("default local login: demo / demo-pass; client: local-cli -> http://127.0.0.1:9876/callback")
	log.Printf("discovery: http://%s/metadata", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
