package cdn

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/edgeguard/platform/internal/cache"
	"github.com/rs/zerolog/log"
)

type Proxy struct {
	cache      *cache.Cache
	httpClient *http.Client
	origins    map[string]*Origin
}

type Origin struct {
	URL         *url.URL
	Weight      int
	Healthy     bool
	LastCheck   time.Time
	FailCount   int
	HealthCheck *HealthCheck
}

type HealthCheck struct {
	Enabled  bool
	Interval time.Duration
	Timeout  time.Duration
	Path     string
}

func NewProxy(cacheInstance *cache.Cache) *Proxy {
	return &Proxy{
		cache: cacheInstance,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
					MinVersion:         tls.VersionTLS12,
				},
				DisableCompression: false,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		origins: make(map[string]*Origin),
	}
}

func (p *Proxy) AddOrigin(name string, originURL string, weight int) error {
	parsed, err := url.Parse(originURL)
	if err != nil {
		return fmt.Errorf("invalid origin URL: %w", err)
	}

	p.origins[name] = &Origin{
		URL:       parsed,
		Weight:    weight,
		Healthy:   true,
		LastCheck: time.Now(),
		FailCount: 0,
	}

	log.Info().Str("origin", name).Str("url", originURL).Msg("Added origin server")

	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, originName string) {
	ctx := r.Context()

	// Generate cache key
	cacheKey := cache.GenerateCacheKey(r.Method, r.URL.String(), r.URL.RawQuery)

	// Try to serve from cache for GET requests
	if r.Method == http.MethodGet {
		if cachedData, found, err := p.cache.Get(ctx, cacheKey); err == nil && found {
			log.Debug().Str("url", r.URL.String()).Msg("Cache hit")
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("X-Cache-Key", cacheKey)
			w.Write(cachedData)
			return
		}
	}

	// Get origin server
	origin, exists := p.origins[originName]
	if !exists || !origin.Healthy {
		log.Error().Str("origin", originName).Msg("Origin not found or unhealthy")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Create proxy request
	proxyReq, err := p.createProxyRequest(r, origin)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create proxy request")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Execute request to origin
	startTime := time.Now()
	resp, err := p.httpClient.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Str("origin", originName).Msg("Failed to proxy request")
		origin.FailCount++
		if origin.FailCount >= 3 {
			origin.Healthy = false
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	duration := time.Since(startTime)
	origin.FailCount = 0 // Reset fail count on success

	log.Info().
		Str("origin", originName).
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Int("status", resp.StatusCode).
		Dur("duration", duration).
		Msg("Proxied request")

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read response body")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Cache successful GET responses
	if r.Method == http.MethodGet && resp.StatusCode == http.StatusOK {
		if err := p.cache.Set(ctx, cacheKey, body, 0); err != nil {
			log.Error().Err(err).Msg("Failed to cache response")
		}
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Add custom headers
	w.Header().Set("X-Cache", "MISS")
	w.Header().Set("X-Cache-Key", cacheKey)
	w.Header().Set("X-Origin-Response-Time", duration.String())
	w.Header().Set("X-Served-By", "EdgeGuard")

	// Write response
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func (p *Proxy) createProxyRequest(r *http.Request, origin *Origin) (*http.Request, error) {
	// Clone the request
	proxyURL := *r.URL
	proxyURL.Scheme = origin.URL.Scheme
	proxyURL.Host = origin.URL.Host

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, proxyURL.String(), r.Body)
	if err != nil {
		return nil, err
	}

	// Copy headers
	for key, values := range r.Header {
		// Skip hop-by-hop headers
		if p.isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Set/override important headers
	proxyReq.Header.Set("X-Forwarded-For", p.getClientIP(r))
	proxyReq.Header.Set("X-Forwarded-Proto", p.getScheme(r))
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)

	return proxyReq, nil
}

func (p *Proxy) isHopByHopHeader(header string) bool {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	header = strings.ToLower(header)
	for _, h := range hopByHop {
		if strings.ToLower(h) == header {
			return true
		}
	}
	return false
}

func (p *Proxy) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip := strings.Split(r.RemoteAddr, ":")[0]
	return ip
}

func (p *Proxy) getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func (p *Proxy) StartHealthChecks(ctx context.Context) {
	for name, origin := range p.origins {
		if origin.HealthCheck != nil && origin.HealthCheck.Enabled {
			go p.healthCheckLoop(ctx, name, origin)
		}
	}
}

func (p *Proxy) healthCheckLoop(ctx context.Context, name string, origin *Origin) {
	ticker := time.NewTicker(origin.HealthCheck.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.performHealthCheck(name, origin)
		}
	}
}

func (p *Proxy) performHealthCheck(name string, origin *Origin) {
	checkURL := origin.URL.String()
	if origin.HealthCheck.Path != "" {
		u, _ := url.Parse(checkURL)
		u.Path = origin.HealthCheck.Path
		checkURL = u.String()
	}

	client := &http.Client{
		Timeout: origin.HealthCheck.Timeout,
	}

	resp, err := client.Get(checkURL)
	if err != nil {
		log.Warn().Err(err).Str("origin", name).Msg("Health check failed")
		origin.Healthy = false
		origin.FailCount++
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if !origin.Healthy {
			log.Info().Str("origin", name).Msg("Origin recovered")
		}
		origin.Healthy = true
		origin.FailCount = 0
	} else {
		log.Warn().Str("origin", name).Int("status", resp.StatusCode).Msg("Health check returned non-2xx status")
		origin.Healthy = false
		origin.FailCount++
	}

	origin.LastCheck = time.Now()
}

func (p *Proxy) GetOriginStats() map[string]interface{} {
	stats := make(map[string]interface{})
	for name, origin := range p.origins {
		stats[name] = map[string]interface{}{
			"healthy":     origin.Healthy,
			"fail_count":  origin.FailCount,
			"last_check":  origin.LastCheck,
			"weight":      origin.Weight,
		}
	}
	return stats
}
