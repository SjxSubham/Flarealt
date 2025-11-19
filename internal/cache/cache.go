package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

type Cache struct {
	client     *redis.Client
	defaultTTL time.Duration
}

type CachedResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Timestamp  time.Time
}

func New(redisURL string, defaultTTL int) (*Cache, error) {
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

	log.Info().Str("redis", redisURL).Msg("Connected to Redis cache")

	return &Cache{
		client:     client,
		defaultTTL: time.Duration(defaultTTL) * time.Second,
	}, nil
}

func (c *Cache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	val, err := c.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return val, true, nil
}

func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}
	return c.client.Set(ctx, key, value, ttl).Err()
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, key).Err()
}

func (c *Cache) Purge(ctx context.Context, pattern string) (int64, error) {
	var cursor uint64
	var deleted int64

	for {
		var keys []string
		var err error
		keys, cursor, err = c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return deleted, err
		}

		if len(keys) > 0 {
			n, err := c.client.Del(ctx, keys...).Result()
			if err != nil {
				return deleted, err
			}
			deleted += n
		}

		if cursor == 0 {
			break
		}
	}

	return deleted, nil
}

func (c *Cache) GetStats(ctx context.Context) (map[string]interface{}, error) {
	info, err := c.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, err
	}

	dbSize, err := c.client.DBSize(ctx).Result()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"info":    info,
		"db_size": dbSize,
	}, nil
}

func GenerateCacheKey(method, url, queryParams string) string {
	data := fmt.Sprintf("%s:%s:%s", method, url, queryParams)
	hash := sha256.Sum256([]byte(data))
	return "cdn:" + hex.EncodeToString(hash[:])
}

func (c *Cache) Close() error {
	return c.client.Close()
}
