package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

type Server struct {
	server     *dns.Server
	cache      *DNSCache
	upstream   []string
	ttl        uint32
	mu         sync.RWMutex
	records    map[string][]dns.RR
}

type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
}

type CacheEntry struct {
	Records   []dns.RR
	ExpiresAt time.Time
}

func NewServer(listenAddr string, upstream []string, ttl int) *Server {
	s := &Server{
		cache:   NewDNSCache(),
		upstream: upstream,
		ttl:     uint32(ttl),
		records: make(map[string][]dns.RR),
	}

	dns.HandleFunc(".", s.handleRequest)

	s.server = &dns.Server{
		Addr: listenAddr,
		Net:  "udp",
	}

	log.Info().Str("addr", listenAddr).Msg("DNS server initialized")

	return s
}

func NewDNSCache() *DNSCache {
	cache := &DNSCache{
		entries: make(map[string]*CacheEntry),
	}
	go cache.cleanupLoop()
	return cache
}

func (c *DNSCache) Get(key string) ([]dns.RR, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.Records, true
}

func (c *DNSCache) Set(key string, records []dns.RR, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &CacheEntry{
		Records:   records,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (c *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if r.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeNotImplemented
		w.WriteMsg(m)
		return
	}

	for _, q := range r.Question {
		log.Debug().
			Str("domain", q.Name).
			Str("type", dns.TypeToString[q.Qtype]).
			Msg("DNS query received")

		// Check cache first
		cacheKey := fmt.Sprintf("%s-%d", q.Name, q.Qtype)
		if cached, found := s.cache.Get(cacheKey); found {
			m.Answer = append(m.Answer, cached...)
			log.Debug().Str("domain", q.Name).Msg("DNS cache hit")
			continue
		}

		// Check local records
		s.mu.RLock()
		if records, exists := s.records[q.Name]; exists {
			for _, rr := range records {
				if rr.Header().Rrtype == q.Qtype || q.Qtype == dns.TypeANY {
					m.Answer = append(m.Answer, rr)
				}
			}
			s.mu.RUnlock()

			if len(m.Answer) > 0 {
				// Cache the result
				s.cache.Set(cacheKey, m.Answer, time.Duration(s.ttl)*time.Second)
				continue
			}
		} else {
			s.mu.RUnlock()
		}

		// Forward to upstream
		upstream := s.queryUpstream(r)
		if upstream != nil {
			m.Answer = append(m.Answer, upstream.Answer...)
			// Cache upstream result
			if len(upstream.Answer) > 0 {
				s.cache.Set(cacheKey, upstream.Answer, time.Duration(s.ttl)*time.Second)
			}
		}
	}

	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}

	w.WriteMsg(m)
}

func (s *Server) queryUpstream(r *dns.Msg) *dns.Msg {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	for _, upstream := range s.upstream {
		resp, _, err := c.Exchange(r, upstream)
		if err != nil {
			log.Warn().Err(err).Str("upstream", upstream).Msg("Upstream DNS query failed")
			continue
		}

		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			return resp
		}
	}

	return nil
}

func (s *Server) AddRecord(domain string, recordType uint16, value string, ttl uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var rr dns.RR
	var err error

	switch recordType {
	case dns.TypeA:
		rr, err = dns.NewRR(fmt.Sprintf("%s %d IN A %s", domain, ttl, value))
	case dns.TypeAAAA:
		rr, err = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", domain, ttl, value))
	case dns.TypeCNAME:
		rr, err = dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", domain, ttl, value))
	case dns.TypeMX:
		rr, err = dns.NewRR(fmt.Sprintf("%s %d IN MX %s", domain, ttl, value))
	case dns.TypeTXT:
		rr, err = dns.NewRR(fmt.Sprintf("%s %d IN TXT \"%s\"", domain, ttl, value))
	default:
		return fmt.Errorf("unsupported record type: %d", recordType)
	}

	if err != nil {
		return err
	}

	if s.records[domain] == nil {
		s.records[domain] = make([]dns.RR, 0)
	}

	s.records[domain] = append(s.records[domain], rr)

	log.Info().
		Str("domain", domain).
		Str("type", dns.TypeToString[recordType]).
		Str("value", value).
		Msg("Added DNS record")

	return nil
}

func (s *Server) RemoveRecord(domain string, recordType uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	records, exists := s.records[domain]
	if !exists {
		return fmt.Errorf("domain not found: %s", domain)
	}

	filtered := make([]dns.RR, 0)
	for _, rr := range records {
		if rr.Header().Rrtype != recordType {
			filtered = append(filtered, rr)
		}
	}

	if len(filtered) == 0 {
		delete(s.records, domain)
	} else {
		s.records[domain] = filtered
	}

	log.Info().
		Str("domain", domain).
		Str("type", dns.TypeToString[recordType]).
		Msg("Removed DNS record")

	return nil
}

func (s *Server) Start() error {
	log.Info().Str("addr", s.server.Addr).Msg("Starting DNS server")
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	log.Info().Msg("Shutting down DNS server")
	return s.server.ShutdownContext(ctx)
}

func (s *Server) GetStats() map[string]interface{} {
	s.mu.RLock()
	recordCount := len(s.records)
	s.mu.RUnlock()

	s.cache.mu.RLock()
	cacheSize := len(s.cache.entries)
	s.cache.mu.RUnlock()

	return map[string]interface{}{
		"records_count": recordCount,
		"cache_size":    cacheSize,
		"upstream":      s.upstream,
	}
}
