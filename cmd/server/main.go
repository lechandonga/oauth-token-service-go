// Command oauth-server 在本地启动身份认证与令牌服务。
// 仅绑定配置中的回环地址，不依赖任何外部账号体系或第三方库。
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/config"
	"github.com/lechandonga/oauth-token-service-go/internal/server"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

func main() {
	cfgPath := flag.String("config", "configs/config.json", "配置文件路径")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	st, err := store.New(cfg.DataFile)
	if err != nil {
		log.Fatalf("open state store: %v", err)
	}

	srv := server.New(cfg, st, time.Now)
	if cfg.RotateInterval.Std() > 0 {
		go rotateLoop(st, cfg.RotateInterval.Std())
	}

	log.Printf("local oauth service listening on http://%s (issuer=%s, data=%s)",
		cfg.ListenAddr, cfg.Issuer, cfg.DataFile)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(httpServer.ListenAndServe())
}

func rotateLoop(st *store.Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := st.NewKey(time.Now()); err != nil {
			log.Printf("key rotation failed: %v", err)
		} else {
			log.Printf("signing key rotated")
		}
	}
}
