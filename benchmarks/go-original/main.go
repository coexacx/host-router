// host-router: 单端口/多端口，按 TLS SNI 或 HTTP Host 把连接透明转发到不同后端。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Rule struct {
	Listen string `json:"listen"`
	Domain string `json:"domain"`
	Target string `json:"target"`
}

type Config struct {
	DefaultPort string `json:"default_port"`
	AccessLog   bool   `json:"access_log"`
	DialTimeoutMS int   `json:"dial_timeout_ms"`
	Rules       []Rule `json:"rules"`
}

type rules struct {
	exact map[string]string
	wild  map[string]string
	def   string
}

type runtimeConfig struct {
	dialTO    time.Duration
	accessLog bool
}

func (rs *rules) lookup(host string) string {
	host = normLookupDomain(host)
	if t, ok := rs.exact[host]; ok {
		return t
	}
	best, bestLen := "", -1
	for suf, t := range rs.wild {
		if strings.HasSuffix(host, suf) && len(suf) > bestLen {
			best, bestLen = t, len(suf)
		}
	}
	if best != "" {
		return best
	}
	return rs.def
}

func normLookupDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	return strings.TrimSuffix(d, ".")
}

func (rs *rules) known() string {
	keys := make([]string, 0, len(rs.exact)+len(rs.wild))
	for k := range rs.exact {
		keys = append(keys, k)
	}
	for k := range rs.wild {
		keys = append(keys, "*"+k)
	}
	sort.Strings(keys)
	if rs.def != "" {
		keys = append(keys, "*(default)")
	}
	if len(keys) == 0 {
		return "(none)"
	}
	return strings.Join(keys, ", ")
}

type listener struct {
	addr   string
	ln     net.Listener
	routes atomic.Pointer[rules]
}

type manager struct {
	cfgPath string
	runtime atomic.Pointer[runtimeConfig]
	dnsCache *dnsCache
	mu       sync.Mutex
	active   map[string]*listener
}

func newManager(cfgPath string) *manager {
	m := &manager{cfgPath: cfgPath, dnsCache: newDNSCache(5 * time.Minute), active: map[string]*listener{}}
	m.runtime.Store(&runtimeConfig{dialTO: 5 * time.Second})
	return m
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func desiredFromConfig(cfg *Config) (map[string]*rules, *runtimeConfig, error) {
	runtime := &runtimeConfig{dialTO: 5 * time.Second, accessLog: cfg.AccessLog}
	if cfg.DialTimeoutMS > 0 {
		runtime.dialTO = time.Duration(cfg.DialTimeoutMS) * time.Millisecond
	}
	if runtime.dialTO < 100*time.Millisecond || runtime.dialTO > 120*time.Second {
		return nil, nil, fmt.Errorf("dial_timeout_ms must be between 100 and 120000")
	}
	rules, err := buildRules(cfg)
	if err != nil {
		return nil, nil, err
	}
	return rules, runtime, nil
}

func buildRules(cfg *Config) (map[string]*rules, error) {
	defPort := strings.TrimSpace(cfg.DefaultPort)
	if defPort == "" {
		defPort = "443"
	}
	if err := validPort(defPort); err != nil {
		return nil, fmt.Errorf("default_port: %w", err)
	}
	out := map[string]*rules{}
	for i, r := range cfg.Rules {
		la, err := normListen(r.Listen)
		if err != nil {
			return nil, fmt.Errorf("rules[%d].listen: %w", i, err)
		}
		tgt, err := withPort(r.Target, defPort)
		if err != nil {
			return nil, fmt.Errorf("rules[%d].target: %w", i, err)
		}
		rs := out[la]
		if rs == nil {
			rs = &rules{exact: map[string]string{}, wild: map[string]string{}}
			out[la] = rs
		}
		d, err := normDomain(r.Domain)
		if err != nil {
			return nil, fmt.Errorf("rules[%d].domain: %w", i, err)
		}
		switch {
		case d == "*":
			if rs.def != "" {
				return nil, fmt.Errorf("rules[%d].domain: duplicate default rule on %s", i, la)
			}
			rs.def = tgt
		case strings.HasPrefix(d, "*."):
			if _, ok := rs.wild[d[1:]]; ok {
				return nil, fmt.Errorf("rules[%d].domain: duplicate wildcard %s on %s", i, d, la)
			}
			rs.wild[d[1:]] = tgt
		default:
			if _, ok := rs.exact[d]; ok {
				return nil, fmt.Errorf("rules[%d].domain: duplicate domain %s on %s", i, d, la)
			}
			rs.exact[d] = tgt
		}
	}
	return out, nil
}

func (m *manager) apply() error {
	cfg, err := loadConfig(m.cfgPath)
	if err != nil {
		return err
	}
	desired, runtime, err := desiredFromConfig(cfg)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	newListeners := map[string]*listener{}
	for addr, rs := range desired {
		if _, ok := m.active[addr]; ok {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, lst := range newListeners {
				_ = lst.ln.Close()
			}
			return fmt.Errorf("listen %s failed: %w", addr, err)
		}
		lst := &listener{addr: addr, ln: ln}
		lst.routes.Store(rs)
		newListeners[addr] = lst
	}

	for addr, lst := range m.active {
		if _, ok := desired[addr]; !ok {
			lst.ln.Close()
			delete(m.active, addr)
			log.Printf("stop listening %s (removed from config)", addr)
		}
	}
	for addr, rs := range desired {
		if lst, ok := m.active[addr]; ok {
			lst.routes.Store(rs)
			log.Printf("reload %s -> %s", addr, rs.known())
			continue
		}
		lst := newListeners[addr]
		m.active[addr] = lst
		go m.serve(lst)
		log.Printf("listening %s -> %s", addr, rs.known())
	}
	m.runtime.Store(runtime)
	if len(m.active) == 0 {
		log.Printf("warning: no active listener (check config / port conflicts)")
	}
	return nil
}

func (m *manager) serve(lst *listener) {
	for {
		c, err := lst.ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				return
			}
			log.Printf("[%s] accept error: %v", lst.addr, err)
			return
		}
		go m.handle(lst, c)
	}
}

func (m *manager) handle(lst *listener, client net.Conn) {
	defer client.Close()
	tuneTCP(client)

	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	host, prefix, err := sniffHost(client)
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("[%s][%s] sniff failed: %v", lst.addr, client.RemoteAddr(), err)
		return
	}

	rs := lst.routes.Load()
	target := rs.lookup(host)
	if target == "" {
		log.Printf("[%s][%s] no route for %q (loaded: %s), drop",
			lst.addr, client.RemoteAddr(), host, rs.known())
		return
	}

	rc := m.runtime.Load()
	if rc.accessLog {
		log.Printf("[%s][%s] %q -> dialing %s", lst.addr, client.RemoteAddr(), host, target)
	}
	backend, err := m.dialTarget(target, rc.dialTO)
	if err != nil {
		log.Printf("[%s][%s] %q -> dial %s FAILED: %v", lst.addr, client.RemoteAddr(), host, target, err)
		return
	}
	defer backend.Close()
	tuneTCP(backend)
	if rc.accessLog {
		log.Printf("[%s][%s] %q -> %s connected", lst.addr, client.RemoteAddr(), host, target)
	}

	pipe(client, backend, prefix)
}

func (m *manager) dialTarget(target string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if net.ParseIP(host) != nil {
		return dialer.Dial("tcp", target)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := m.dnsCache.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last != nil {
		return nil, last
	}
	return nil, net.ErrClosed
}

func tuneTCP(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
}

func pipe(client, backend net.Conn, prefix []byte) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if len(prefix) > 0 {
			if _, err := backend.Write(prefix); err != nil {
				closeConn(backend)
				return
			}
		}
		_, _ = io.Copy(backend, client)
		closeWrite(backend)
		closeRead(client)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, backend)
		closeWrite(client)
		closeRead(backend)
	}()
	wg.Wait()
	closeConn(client)
	closeConn(backend)
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	_ = c.Close()
}

func closeRead(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseRead()
	}
}

func closeConn(c net.Conn) {
	_ = c.Close()
}

func validPort(p string) error {
	if p == "" {
		return fmt.Errorf("empty port")
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	return nil
}

func normListen(l string) (string, error) {
	l = strings.TrimSpace(l)
	if l == "" {
		return "", fmt.Errorf("empty listen address")
	}
	if !strings.Contains(l, ":") {
		if err := validPort(l); err != nil {
			return "", err
		}
		return ":" + l, nil
	}
	if host, port, err := net.SplitHostPort(l); err == nil {
		if err := validPort(port); err != nil {
			return "", err
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			return ":" + port, nil
		}
		return l, nil
	}
	if strings.HasPrefix(l, ":") {
		port := strings.TrimPrefix(l, ":")
		if err := validPort(port); err != nil {
			return "", err
		}
		return ":" + port, nil
	}
	return "", fmt.Errorf("must be a port, :port, host:port, or [ipv6]:port")
}

func normDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", fmt.Errorf("empty domain")
	}
	if d == "*" {
		return d, nil
	}
	if strings.HasPrefix(d, "*.") {
		if err := validHostName(d[2:]); err != nil {
			return "", err
		}
		return d, nil
	}
	if strings.Contains(d, "*") {
		return "", fmt.Errorf("wildcard is only supported as *.example.com")
	}
	if err := validHostName(d); err != nil {
		return "", err
	}
	return d, nil
}

func validHostName(h string) error {
	h = strings.TrimSpace(h)
	if h == "" {
		return fmt.Errorf("empty host")
	}
	if len(h) > 253 {
		return fmt.Errorf("host is too long")
	}
	if strings.ContainsAny(h, " \t\r\n/\\") {
		return fmt.Errorf("host contains invalid characters")
	}
	if strings.Contains(h, ":") && net.ParseIP(h) == nil {
		return fmt.Errorf("host contains ':' but is not an IP address")
	}
	if ip := net.ParseIP(h); ip != nil {
		return nil
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid host label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("host label cannot start or end with '-'")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return fmt.Errorf("host contains invalid characters")
		}
	}
	return nil
}

func withPort(addr, defPort string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.Contains(addr, "://") {
		return "", fmt.Errorf("target must not include a URL scheme")
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		host, port, _ := net.SplitHostPort(addr)
		if err := validHostName(host); err != nil {
			return "", err
		}
		if err := validPort(port); err != nil {
			return "", err
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.Count(addr, ":") > 1 {
		if net.ParseIP(addr) == nil {
			return "", fmt.Errorf("IPv6 target with port must use [ipv6]:port")
		}
		return net.JoinHostPort(addr, defPort), nil
	}
	if strings.Contains(addr, ":") {
		return "", fmt.Errorf("target with port must be host:port or [ipv6]:port")
	}
	if err := validHostName(addr); err != nil {
		return "", err
	}
	return net.JoinHostPort(addr, defPort), nil
}

func main() {
	cfgPath := flag.String("c", "config.json", "config file path")
	check := flag.Bool("check", false, "validate config and exit")
	flag.Parse()

	if *check {
		cfg, err := loadConfig(*cfgPath)
		if err != nil {
			log.Fatalf("load config failed: %v", err)
		}
		if _, _, err := desiredFromConfig(cfg); err != nil {
			log.Fatalf("config invalid: %v", err)
		}
		log.Printf("config ok")
		return
	}

	m := newManager(*cfgPath)
	if err := m.apply(); err != nil {
		log.Fatalf("load config failed: %v", err)
	}
	installReload(m)
	<-context.Background().Done()
}
