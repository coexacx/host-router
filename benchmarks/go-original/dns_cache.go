package main

import (
	"context"
	"net"
	"sync"
	"time"
)

type dnsEntry struct {
	ips []net.IP
	exp time.Time
}

type dnsCache struct {
	ttl time.Duration
	mu  sync.RWMutex
	m   map[string]dnsEntry
}

func newDNSCache(ttl time.Duration) *dnsCache {
	return &dnsCache{ttl: ttl, m: map[string]dnsEntry{}}
}

func (c *dnsCache) lookup(ctx context.Context, host string) ([]net.IP, error) {
	now := time.Now()
	c.mu.RLock()
	if e, ok := c.m[host]; ok && now.Before(e.exp) && len(e.ips) > 0 {
		ips := append([]net.IP(nil), e.ips...)
		c.mu.RUnlock()
		return ips, nil
	}
	c.mu.RUnlock()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			ips = append(ips, addr.IP)
		}
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host}
	}

	c.mu.Lock()
	c.m[host] = dnsEntry{ips: append([]net.IP(nil), ips...), exp: now.Add(c.ttl)}
	c.mu.Unlock()
	return ips, nil
}
