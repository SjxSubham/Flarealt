package ddos

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

type Shield struct {
	redis         *redis.Client
	threshold     int
	windowSize    time.Duration
	blacklistTTL  time.Duration
	mu            sync.RWMutex
	localCounters map[string]*RequestCounter
}

type RequestCounter struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

type AttackType int

const (
	HTTPFlood AttackType = iota
	SYNFlood
	UDPFlood
	SlowLoris
	LayerSevenDDoS
)

func NewShield(redisURL string, threshold int) (*Shield, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}

	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	shield := &Shield{
		redis:         client,
		threshold:     threshold,
		windowSize:    time.Minute,
		blacklistTTL:  time.Hour,
		localCounters: make(map[string]*RequestCounter),
	}

	// Start cleanup goroutine
	go shield.cleanupLoop()

	log.Info().Int("threshold", threshold).Msg("DDoS Shield initialized")

	return shield, nil
}

func (s *Shield) CheckRequest(ctx context.Context, ip string) (bool, error) {
	// Check if IP is blacklisted
	blacklisted, err := s.isBlacklisted(ctx, ip)
	if err != nil {
		log.Error().Err(err).Str("ip", ip).Msg("Failed to check blacklist")
		return false, err
	}
	if blacklisted {
		log.Warn().Str("ip", ip).Msg("Blocked blacklisted IP")
		return false, nil
	}

	// Increment request counter
	count, err := s.incrementCounter(ctx, ip)
	if err != nil {
		return false, err
	}

	// Check if threshold exceeded
	if count > s.threshold {
		// Blacklist the IP
		if err := s.blacklist(ctx, ip); err != nil {
			log.Error().Err(err).Str("ip", ip).Msg("Failed to blacklist IP")
		}
		log.Warn().Str("ip", ip).Int("count", count).Msg("DDoS detected - IP blacklisted")
		return false, nil
	}

	return true, nil
}

func (s *Shield) incrementCounter(ctx context.Context, ip string) (int, error) {
	key := fmt.Sprintf("ddos:counter:%s", ip)
	
	pipe := s.redis.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, s.windowSize)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return int(incr.Val()), nil
}

func (s *Shield) isBlacklisted(ctx context.Context, ip string) (bool, error) {
	key := fmt.Sprintf("ddos:blacklist:%s", ip)
	exists, err := s.redis.Exists(ctx, key).Result()
	return exists > 0, err
}

func (s *Shield) blacklist(ctx context.Context, ip string) error {
	key := fmt.Sprintf("ddos:blacklist:%s", ip)
	return s.redis.Set(ctx, key, time.Now().Unix(), s.blacklistTTL).Err()
}

func (s *Shield) Whitelist(ctx context.Context, ip string) error {
	key := fmt.Sprintf("ddos:blacklist:%s", ip)
	return s.redis.Del(ctx, key).Err()
}

func (s *Shield) GetStats(ctx context.Context) (map[string]interface{}, error) {
	// Count blacklisted IPs
	var cursor uint64
	var blacklisted int

	for {
		var keys []string
		var err error
		keys, cursor, err = s.redis.Scan(ctx, cursor, "ddos:blacklist:*", 100).Result()
		if err != nil {
			return nil, err
		}
		blacklisted += len(keys)
		if cursor == 0 {
			break
		}
	}

	return map[string]interface{}{
		"blacklisted_ips": blacklisted,
		"threshold":       s.threshold,
		"window_size":     s.windowSize.String(),
	}, nil
}

func (s *Shield) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for ip, counter := range s.localCounters {
			if now.Sub(counter.LastSeen) > s.windowSize {
				delete(s.localCounters, ip)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Shield) DetectAttackType(requestRate int, connectionCount int, payloadSize int) AttackType {
	if requestRate > s.threshold*10 {
		return HTTPFlood
	}
	if connectionCount > 1000 && payloadSize < 100 {
		return SYNFlood
	}
	if payloadSize > 65000 {
		return UDPFlood
	}
	return LayerSevenDDoS
}

func (s *Shield) IsPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func (s *Shield) Close() error {
	return s.redis.Close()
}
