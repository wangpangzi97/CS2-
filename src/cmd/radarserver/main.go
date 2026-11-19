// Production data service: device-bound authorization; no legacy shared token.
package main

import (
	"context"
	"flag"
	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/radarsrv"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

var (
	replayConfig = flag.String("restricted-replay-config", "", "optional explicit private one-session gameplay replay consent file; OFF by default")
	listen       = flag.String("listen", "127.0.0.1:18081", "listener (loopback by default)")
	audience     = flag.String("public-origin", "", "required exact HTTPS origin used by clients")
	php          = flag.String("php-binary", "", "required absolute trusted PHP executable path")
	script       = flag.String("authority-script", "", "required absolute license-authority-cli.php path")
	project      = flag.String("guyi-project", "", "required absolute GuYi root with additive data-auth migration and patched Database.php")
	appID        = flag.Int("app-id", 0, "required licensed application ID")
	proxy        = flag.Bool("trust-loopback-proxy", false, "only for a loopback nginx listener overwriting X-GS-Client-IP and X-GS-TLS")
	cert         = flag.String("tls-cert", "", "TLS certificate (required unless explicit loopback proxy)")
	key          = flag.String("tls-key", "", "TLS private key")
	mapDir       = flag.String("mapimg", "", "server-side map image assets")
)

func main() {
	flag.Parse()
	if *audience == "" || *php == "" || *script == "" || *project == "" || *appID < 1 {
		log.Fatal("data authority configuration required; legacy tokens are disabled")
	}
	if !filepath.IsAbs(*php) || !filepath.IsAbs(*script) || !filepath.IsAbs(*project) {
		log.Fatal("trusted absolute backend paths required")
	}
	for _, p := range []string{*php, *script, *project} {
		if _, e := os.Stat(p); e != nil {
			log.Fatal("backend path unavailable")
		}
	}
	if (*cert == "") != (*key == "") {
		log.Fatal("TLS pair required")
	}
	if *cert == "" {
		host, _, e := net.SplitHostPort(*listen)
		ip, e2 := netip.ParseAddr(host)
		if e != nil || e2 != nil || !ip.IsLoopback() || !*proxy {
			log.Fatal("HTTPS required; plaintext allowed only behind explicit loopback TLS proxy")
		}
	}
	authority := &dataauth.CommandAuthority{PHP: *php, Script: *script, Project: *project, AppID: *appID}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	e := authority.Ready(ctx)
	cancel()
	if e != nil {
		log.Fatal("license authority/schema unavailable; refusing start")
	}
	cfg := radarsrv.DefaultConfig()
	if *replayConfig != "" {
		cfg.RestrictedReplay = optionalReplay(*replayConfig)
	}
	cfg.MapImageDir = *mapDir
	store := radarsrv.NewStore(cfg)
	broker, e := dataauth.NewBroker(dataauth.BrokerConfig{Audience: *audience, Authority: authority, TrustLoopbackProxy: *proxy, OnRevoke: store.DropAuthorizedSession})
	if e != nil {
		log.Fatal("invalid data authority configuration")
	}
	go broker.Run(context.Background())
	server := &http.Server{Addr: *listen, Handler: store.SecureHandler(broker), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	log.Printf("device-bound data service listening on %s; signed pixel view only; no raw view or legacy token endpoints", *listen)
	if *cert != "" {
		log.Fatal(server.ListenAndServeTLS(*cert, *key))
	}
	log.Fatal(server.ListenAndServe())
}
