package mastervpncore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultListenHost  = "127.0.0.1"
	defaultListenPort  = 8085
	defaultGoogleIP    = "216.239.38.120"
	defaultFrontDomain = "www.google.com"
)

type Config struct {
	Mode        string            `json:"mode"`
	ListenHost  string            `json:"listen_host"`
	ListenPort  int               `json:"listen_port"`
	TunMTU      int               `json:"tun_mtu"`
	DNSResolver string            `json:"dns_resolver"`
	GoogleIP    string            `json:"google_ip"`
	FrontDomain string            `json:"front_domain"`
	ScriptID    string            `json:"script_id"`
	AuthKey     string            `json:"auth_key"`
	VerifySSL   bool              `json:"verify_ssl"`
	Hosts       map[string]string `json:"hosts"`
}

type RelayPayload struct {
	Method  string            `json:"m"`
	URL     string            `json:"u"`
	Headers map[string]string `json:"h,omitempty"`
	Body    string            `json:"b,omitempty"`
	Type    string            `json:"ct,omitempty"`
	Raw     bool              `json:"r"`
	AuthKey string            `json:"k"`
}

type RelayResult struct {
	Status  int
	Headers http.Header
	Body    []byte
}

type Proxy struct {
	cfg      Config
	relay    *RelayClient
	server   *http.Server
	listener net.Listener
}

type RelayClient struct {
	cfg       Config
	client    *http.Client
	execURL   string
	dialer    net.Dialer
	transport *http.Transport
}

var runtimeState = struct {
	sync.Mutex
	proxy  *Proxy
	bridge *TunBridge
}{}

func StartProxy(configJSON string) string {
	return StartVpn(configJSON, -1)
}

func StartVpn(configJSON string, tunFD int32) string {
	runtimeState.Lock()
	defer runtimeState.Unlock()

	if runtimeState.proxy != nil {
		return marshalStatus("already_running", map[string]any{
			"listen": runtimeState.proxy.listener.Addr().String(),
		})
	}

	cfg, err := parseConfig(configJSON)
	if err != nil {
		return marshalError(err)
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		return marshalError(err)
	}

	var bridge *TunBridge
	if tunFD >= 0 {
		bridge, err = NewTunBridge(tunFD, cfg)
		if err != nil {
			return marshalError(err)
		}
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort)))
	if err != nil {
		if bridge != nil {
			bridge.Close()
		}
		return marshalError(err)
	}

	proxy.listener = listener
	proxy.server = &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           proxy,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	runtimeState.proxy = proxy
	runtimeState.bridge = bridge

	go func() {
		if err := proxy.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("mastervpncore: proxy serve failed: %v", err)
		}
		untimeReset(proxy, bridge)
	}()

	status := map[string]any{
		"listen": listener.Addr().String(),
		"mode":   cfg.Mode,
	}
	if bridge != nil {
		status["tun_bridge"] = "active"
	}
	return marshalStatus("started", status)
}

func StopProxy() string {
	runtimeState.Lock()
	proxy := runtimeState.proxy
	bridge := runtimeState.bridge
	runtimeState.Unlock()

	if proxy == nil {
		return marshalStatus("stopped", map[string]any{
			"message": "proxy not running",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := proxy.server.Shutdown(ctx); err != nil {
		return marshalError(err)
	}
	if bridge != nil {
		bridge.Close()
	}

	untimeReset(proxy, bridge)
	return marshalStatus("stopped", map[string]any{"message": "proxy stopped"})
}

func NewProxy(cfg Config) (*Proxy, error) {
	relay, err := NewRelayClient(cfg)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		cfg:   cfg,
		relay: relay,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	if err := p.handleHTTP(w, r); err != nil {
		log.Printf("mastervpncore: HTTP relay failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	defer r.Body.Close()

	targetURL := absoluteProxyURL(r)
	payload := RelayPayload{
		Method:  r.Method,
		URL:     targetURL,
		Headers: flattenHeaders(r.Header),
		Raw:     true,
		AuthKey: p.cfg.AuthKey,
	}
	if len(body) > 0 {
		payload.Body = base64.StdEncoding.EncodeToString(body)
		payload.Type = r.Header.Get("Content-Type")
	}

	result, err := p.relay.Submit(r.Context(), payload)
	if err != nil {
		return err
	}

	copyHeaders(w.Header(), result.Headers)
	w.Header().Set("Content-Length", strconv.Itoa(len(result.Body)))
	w.WriteHeader(result.Status)
	_, err = w.Write(result.Body)
	return err
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Mode == "apps_script" {
		p.handleAppsScriptConnect(w, r)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	targetAddr := hostPortForConnect(r.Host)
	dialer := newProtectedNetDialer()
	serverConn, err := (&dialer).Dial("tcp", targetAddr)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		_ = clientConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	if rw.Reader.Buffered() > 0 {
		buffered, _ := rw.Reader.Peek(rw.Reader.Buffered())
		_, _ = serverConn.Write(buffered)
		_, _ = rw.Reader.Discard(len(buffered))
	}

	go proxyCopy(serverConn, clientConn)
	go proxyCopy(clientConn, serverConn)
}

func (p *Proxy) handleAppsScriptConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	reader := rw.Reader
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("mastervpncore: CONNECT relay read failed: %v", err)
			}
			return
		}

		if req.URL == nil || (!req.URL.IsAbs() && req.URL.Scheme == "") {
			// CONNECT streams are often TLS payload, not plaintext HTTP.
			// In apps_script mode we only relay parseable HTTP messages.
			writeTunnelError(clientConn, http.StatusNotImplemented, "CONNECT payload is not HTTP and cannot be relayed via Apps Script")
			_ = req.Body.Close()
			return
		}

		body, berr := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if berr != nil {
			writeTunnelError(clientConn, http.StatusBadGateway, "Failed to read tunneled request body")
			return
		}

		targetURL := buildConnectRelayURL(req, r.Host)
		payload := RelayPayload{
			Method:  req.Method,
			URL:     targetURL,
			Headers: flattenHeaders(req.Header),
			Raw:     true,
			AuthKey: p.cfg.AuthKey,
		}
		if len(body) > 0 {
			payload.Body = base64.StdEncoding.EncodeToString(body)
			payload.Type = req.Header.Get("Content-Type")
		}

		result, rerr := p.relay.Submit(context.Background(), payload)
		if rerr != nil {
			writeTunnelError(clientConn, http.StatusBadGateway, "Relay request failed: "+rerr.Error())
			return
		}

		if _, werr := clientConn.Write(rawHTTPResponse(result)); werr != nil {
			return
		}

		if shouldCloseTunnel(req) {
			return
		}
	}
}

func proxyCopy(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func NewRelayClient(cfg Config) (*RelayClient, error) {
	if cfg.ScriptID == "" {
		return nil, errors.New("missing script_id in config")
	}

	dialer := newProtectedNetDialer()
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "443"
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(cfg.GoogleIP, port))
		},
		TLSClientConfig: &tls.Config{
			ServerName:         cfg.FrontDomain,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !cfg.VerifySSL,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
	}

	return &RelayClient{
		cfg:       cfg,
		client:    client,
		execURL:   fmt.Sprintf("https://script.google.com/macros/s/%s/exec", cfg.ScriptID),
		dialer:    dialer,
		transport: transport,
	}, nil
}

func (c *RelayClient) Submit(ctx context.Context, payload RelayPayload) (*RelayResult, error) {
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal relay payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.execURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("build relay request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read relay response: %w", err)
	}

	return parseRelayResponse(body)
}

func parseConfig(configJSON string) (Config, error) {
	cfg := Config{
		Mode:        "apps_script",
		ListenHost:  defaultListenHost,
		ListenPort:  defaultListenPort,
		TunMTU:      1500,
		DNSResolver: "8.8.8.8:53",
		GoogleIP:    defaultGoogleIP,
		FrontDomain: defaultFrontDomain,
		VerifySSL:   true,
	}
	if strings.TrimSpace(configJSON) == "" {
		return cfg, errors.New("empty config JSON")
	}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return cfg, fmt.Errorf("parse config JSON: %w", err)
	}
	if cfg.ListenHost == "" {
		cfg.ListenHost = defaultListenHost
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = defaultListenPort
	}
	if cfg.TunMTU <= 0 {
		cfg.TunMTU = 1500
	}
	if cfg.DNSResolver == "" {
		cfg.DNSResolver = "8.8.8.8:53"
	}
	if cfg.GoogleIP == "" {
		cfg.GoogleIP = defaultGoogleIP
	}
	if cfg.FrontDomain == "" {
		cfg.FrontDomain = defaultFrontDomain
	}
	return cfg, nil
}

func parseRelayResponse(body []byte) (*RelayResult, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return nil, errors.New("empty response from relay")
	}

	jsonText := text
	if !strings.HasPrefix(jsonText, "{") {
		start := strings.IndexByte(text, '{')
		end := strings.LastIndexByte(text, '}')
		if start < 0 || end <= start {
			return nil, fmt.Errorf("no relay JSON in response: %s", trimForLog(text))
		}
		jsonText = text[start : end+1]
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(jsonText), &data); err != nil {
		return nil, fmt.Errorf("decode relay JSON: %w", err)
	}

	if relayErr, ok := data["e"].(string); ok && relayErr != "" {
		return nil, fmt.Errorf("relay error: %s", relayErr)
	}

	status := 200
	if rawStatus, ok := data["s"]; ok {
		switch value := rawStatus.(type) {
		case float64:
			status = int(value)
		case int:
			status = value
		}
	}

	headers := make(http.Header)
	if rawHeaders, ok := data["h"].(map[string]any); ok {
		for key, rawValue := range rawHeaders {
			switch value := rawValue.(type) {
			case string:
				headers.Add(key, value)
			case []any:
				for _, item := range value {
					headers.Add(key, fmt.Sprint(item))
				}
			default:
				headers.Add(key, fmt.Sprint(value))
			}
		}
	}

	decodedBody := []byte{}
	if rawBody, ok := data["b"].(string); ok && rawBody != "" {
		var err error
		decodedBody, err = base64.StdEncoding.DecodeString(rawBody)
		if err != nil {
			return nil, fmt.Errorf("decode relay body: %w", err)
		}
	}

	return &RelayResult{Status: status, Headers: headers, Body: decodedBody}, nil
}

func absoluteProxyURL(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.String()
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	u := *r.URL
	u.Scheme = scheme
	if u.Host == "" {
		u.Host = r.Host
	}
	return u.String()
}

func flattenHeaders(src http.Header) map[string]string {
	out := make(map[string]string, len(src))
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "proxy-connection" || lower == "connection" || lower == "accept-encoding" {
			continue
		}
		out[key] = strings.Join(values, ", ")
	}
	return out
}

func copyHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "transfer-encoding" || lower == "connection" || lower == "keep-alive" || lower == "content-length" {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func hostPortForConnect(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "443")
}

func buildConnectRelayURL(req *http.Request, connectHost string) string {
	if req.URL != nil && req.URL.IsAbs() {
		return req.URL.String()
	}

	host := req.Host
	if host == "" {
		host = connectHost
	}
	host = stripDefaultPort(host)

	path := "/"
	if req.URL != nil {
		path = req.URL.RequestURI()
	}
	if path == "" {
		path = "/"
	}

	return "https://" + host + path
}

func rawHTTPResponse(result *RelayResult) []byte {
	if result == nil {
		return []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	}

	statusText := http.StatusText(result.Status)
	if statusText == "" {
		statusText = "OK"
	}

	var b strings.Builder
	b.WriteString("HTTP/1.1 ")
	b.WriteString(strconv.Itoa(result.Status))
	b.WriteByte(' ')
	b.WriteString(statusText)
	b.WriteString("\r\n")

	for key, values := range result.Headers {
		lower := strings.ToLower(key)
		if lower == "connection" || lower == "transfer-encoding" || lower == "keep-alive" || lower == "content-length" {
			continue
		}
		for _, value := range values {
			b.WriteString(textproto.CanonicalMIMEHeaderKey(key))
			b.WriteString(": ")
			b.WriteString(value)
			b.WriteString("\r\n")
		}
	}

	b.WriteString("Content-Length: ")
	b.WriteString(strconv.Itoa(len(result.Body)))
	b.WriteString("\r\n\r\n")

	return append([]byte(b.String()), result.Body...)
}

func writeTunnelError(conn net.Conn, status int, message string) {
	resp := &RelayResult{
		Status: status,
		Headers: http.Header{
			"Content-Type": []string{"text/plain; charset=utf-8"},
		},
		Body: []byte(message),
	}
	_, _ = conn.Write(rawHTTPResponse(resp))
}

func shouldCloseTunnel(req *http.Request) bool {
	if req == nil {
		return true
	}
	if strings.EqualFold(req.Header.Get("Connection"), "close") {
		return true
	}
	return false
}

func stripDefaultPort(host string) string {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if p == "80" || p == "443" {
		return h
	}
	return host
}

func trimForLog(input string) string {
	if len(input) > 200 {
		return input[:200]
	}
	return input
}

func marshalStatus(status string, extra map[string]any) string {
	payload := map[string]any{"status": status}
	for key, value := range extra {
		payload[key] = value
	}
	encoded, _ := json.Marshal(payload)
	return string(encoded)
}

func marshalError(err error) string {
	encoded, _ := json.Marshal(map[string]any{
		"status":  "error",
		"message": err.Error(),
	})
	return string(encoded)
}

func untimeReset(proxy *Proxy, bridge *TunBridge) {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if runtimeState.proxy == proxy {
		runtimeState.proxy = nil
	}
	if runtimeState.bridge == bridge {
		runtimeState.bridge = nil
	}
}
