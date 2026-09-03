package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/corazawaf/coraza/v3"
	corazaHttp "github.com/corazawaf/coraza/v3/http"
	coreruleset "github.com/corazawaf/coraza-coreruleset"
)

func main() {
	cfg := coraza.NewWAFConfig().
		WithDirectives(`
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
`).
		WithRootFS(coreruleset.FS).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf")

	patchBytes, err := os.ReadFile("patch.conf")
	if err == nil && len(patchBytes) > 0 {
		log.Println("Applying WAF-Checker virtual patch rules (patch.conf)...")
		cfg = cfg.WithDirectives(string(patchBytes))
	} else if err != nil {
		log.Printf("patch.conf note: %v", err)
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		log.Fatalf("failed to create Coraza WAF: %v", err)
	}

	backendURL, err := url.Parse("http://127.0.0.1:8081")
	if err != nil {
		log.Fatalf("invalid backend URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	handler := corazaHttp.WrapHandler(waf, proxy)

	log.Println("Coraza WAF reverse proxy (Patched) listening on :8093 -> forwarding to http://127.0.0.1:8081")
	if err := http.ListenAndServe(":8093", handler); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
