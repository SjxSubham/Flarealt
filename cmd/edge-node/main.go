package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/edgeguard/platform/internal/cache"
	"github.com/edgeguard/platform/internal/cdn"
	"github.com/edgeguard/platform/internal/ddos"
	"github.com/edgeguard/platform/internal/waf"
	"github.com/edgeguard/platform/pkg/config"
	"github.com/edgeguard/platform/pkg/logger"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

type EdgeNode struct {
	config *config.Config
	cache  *cache.Cache
	ddos   *ddos.Shield
	waf    *waf.WAF
	proxy  *cdn.Proxy
	router *mux.Router
}

func main() {
	configPath := flag.String("config", "configs/config.yaml", "Path to config file")
	flag.Parse()

	// Initialize logger
	logger.Init("info")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	log.Info().Str("node_id", cfg.Node.ID).Str("region", cfg.Node.Region).Msg("Starting EdgeGuard Node")

	// Initialize components
	node, err := NewEdgeNode(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize edge node")
	}

	// Start servers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start health checks
	go node.proxy.StartHealthChecks(ctx)

	// HTTP server
	httpServer := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:        node.router,
		ReadTimeout:    cfg.GetReadTimeout(),
		WriteTimeout:   cfg.GetWriteTimeout(),
		MaxHeaderBytes: cfg.Server.MaxHeaderSize,
	}

	// Admin/metrics server
	adminMux := http.NewServeMux()
	adminMux.Handle("/metrics", promhttp.Handler())
	adminMux.HandleFunc("/health", node.healthHandler)
	adminMux.HandleFunc("/stats", node.statsHandler)

	adminServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.AdminPort),
		Handler: adminMux,
	}

	// Start servers
	go func() {
		log.Info().Int("port", cfg.Server.HTTPPort).Msg("Starting HTTP server")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	go func() {
		log.Info().Int("port", cfg.Server.AdminPort).Msg("Starting admin server")
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Admin server error")
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down gracefully...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	}

	if err := adminServer.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("Admin server shutdown error")
	}

	log.Info().Msg("Shutdown complete")
}

func NewEdgeNode(cfg *config.Config) (*EdgeNode, error) {
	// Initialize cache
	cacheInstance, err := cache.New(cfg.Cache.RedisURL, cfg.Cache.TTLDefault)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Initialize DDoS shield
	ddosShield, err := ddos.NewShield(cfg.Cache.RedisURL, cfg.Security.DDoSThreshold)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DDoS shield: %w", err)
	}

	// Initialize WAF
	wafEngine := waf.New(cfg.Security.EnableWAF)

	// Initialize CDN proxy
	proxy := cdn.NewProxy(cacheInstance)

	// Add origins from config
	for _, origin := range cfg.Origins {
		originURL := fmt.Sprintf("%s://%s:%d", origin.Protocol, origin.Host, origin.Port)
		if err := proxy.AddOrigin(origin.Name, originURL, origin.Weight); err != nil {
			return nil, fmt.Errorf("failed to add origin %s: %w", origin.Name, err)
		}
	}

	// Initialize router
	router := mux.NewRouter()

	node := &EdgeNode{
		config: cfg,
		cache:  cacheInstance,
		ddos:   ddosShield,
		waf:    wafEngine,
		proxy:  proxy,
		router: router,
	}

	// Setup routes
	router.Use(node.loggingMiddleware)
	router.Use(node.ddosMiddleware)
	router.Use(node.wafMiddleware)
	router.PathPrefix("/").HandlerFunc(node.proxyHandler)

	return node, nil
}

func (n *EdgeNode) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_addr", r.RemoteAddr).
			Dur("duration", time.Since(start)).
			Msg("Request processed")
	})
}

func (n *EdgeNode) ddosMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		allowed, err := n.ddos.CheckRequest(r.Context(), ip)
		if err != nil {
			log.Error().Err(err).Msg("DDoS check error")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			log.Warn().Str("ip", ip).Msg("Request blocked by DDoS protection")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (n *EdgeNode) wafMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, rule := n.waf.CheckRequest(r)

		if !allowed {
			log.Warn().
				Str("ip", getClientIP(r)).
				Str("rule_id", rule.ID).
				Str("rule_name", rule.Name).
				Msg("Request blocked by WAF")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":    "Forbidden",
				"message":  "Request blocked by Web Application Firewall",
				"rule_id":  rule.ID,
				"severity": rule.Severity,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (n *EdgeNode) proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Default to first origin if only one exists
	originName := "default"
	if len(n.config.Origins) > 0 {
		originName = n.config.Origins[0].Name
	}

	n.proxy.ServeHTTP(w, r, originName)
}

func (n *EdgeNode) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "healthy",
		"node_id": n.config.Node.ID,
		"region": n.config.Node.Region,
		"timestamp": time.Now().Unix(),
	})
}

func (n *EdgeNode) statsHandler(w http.ResponseWriter, r *http.Request) {
	cacheStats, _ := n.cache.GetStats(r.Context())
	ddosStats, _ := n.ddos.GetStats(r.Context())
	originStats := n.proxy.GetOriginStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cache":   cacheStats,
		"ddos":    ddosStats,
		"origins": originStats,
		"waf": map[string]interface{}{
			"rules_count": len(n.waf.GetRules()),
		},
	})
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}
