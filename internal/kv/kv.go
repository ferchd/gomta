// Package kv provides the small key/value surface used by rate limiting and
// greylisting. Redis is used when configured; otherwise an in-process store is
// used (fine for single-node setups, not shared across processes).
package kv

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store is a minimal TTL key/value interface.
type Store interface {
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Close() error
}

var (
	mu    sync.Mutex
	cache = make(map[string]Store)
)

// Open returns a shared store for url. An empty URL returns a process-local
// memory store. redis:// and rediss:// URLs use go-redis.
func Open(url string) (Store, error) {
	mu.Lock()
	defer mu.Unlock()
	if s, ok := cache[url]; ok {
		return s, nil
	}
	var (
		s   Store
		err error
	)
	if url == "" {
		s = NewMemory()
	} else {
		s, err = newRedis(url)
		if err != nil {
			return nil, err
		}
	}
	cache[url] = s
	return s, nil
}

type redisStore struct {
	client *redis.Client
}

func newRedis(url string) (Store, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &redisStore{client: client}, nil
}

func (r *redisStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	// INCR + EXPIRE only for the first increment is atomic and preserves a
	// fixed TTL window, matching memoryStore. Repeated requests must not
	// extend the expiry indefinitely.
	const script = `local n = redis.call('INCR', KEYS[1])
if n == 1 and tonumber(ARGV[1]) > 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return n`
	return r.client.Eval(ctx, script, []string{key}, ttl.Milliseconds()).Int64()
}

func (r *redisStore) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (r *redisStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *redisStore) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *redisStore) Close() error { return r.client.Close() }

type memoryStore struct {
	mu     sync.Mutex
	values map[string]memoryValue
	stop   chan struct{}
	once   sync.Once
}

type memoryValue struct {
	value   string
	expires time.Time
}

// NewMemory returns a standalone in-memory store.
func NewMemory() Store {
	m := &memoryStore{values: make(map[string]memoryValue), stop: make(chan struct{})}
	go m.janitor()
	return m
}

func (m *memoryStore) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			now := time.Now()
			m.mu.Lock()
			for k, v := range m.values {
				if !v.expires.IsZero() && now.After(v.expires) {
					delete(m.values, k)
				}
			}
			m.mu.Unlock()
		case <-m.stop:
			return
		}
	}
}

func (m *memoryStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	v, ok := m.values[key]
	if !ok || (!v.expires.IsZero() && now.After(v.expires)) {
		v = memoryValue{value: "0", expires: now.Add(ttl)}
	}
	n := int64(0)
	for _, c := range v.value {
		if c < '0' || c > '9' {
			n = 0
			break
		}
		n = n*10 + int64(c-'0')
	}
	n++
	v.value = itoa(n)
	m.values[key] = v
	return n, nil
}

func (m *memoryStore) Get(ctx context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[key]
	if !ok {
		return "", false, nil
	}
	if !v.expires.IsZero() && time.Now().After(v.expires) {
		delete(m.values, key)
		return "", false, nil
	}
	return v.value, true, nil
}

func (m *memoryStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	expires := time.Time{}
	if ttl > 0 {
		expires = time.Now().Add(ttl)
	}
	m.values[key] = memoryValue{value: value, expires: expires}
	return nil
}

func (m *memoryStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.values, key)
	return nil
}

func (m *memoryStore) Close() error {
	m.once.Do(func() { close(m.stop) })
	return nil
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
