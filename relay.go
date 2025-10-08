//go:build relay
// +build relay

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
)

type NetworkInfo struct {
	InviteCode string
	CACert     string
	CAKey      string
	RelayIP    string
	HostIP     string
	Subnet     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

type RelayServer struct {
	apiKey   string
	relayIP  string
	networks map[string]*NetworkInfo
	mu       sync.RWMutex
	limiter  *rate.Limiter
}

func NewRelayServer(apiKey, relayIP string) *RelayServer {
	return &RelayServer{
		apiKey:   apiKey,
		relayIP:  relayIP,
		networks: make(map[string]*NetworkInfo),
		limiter:  rate.NewLimiter(rate.Every(time.Second), 10),
	}
}

func generateInviteCode() string {
	b := make([]byte, InviteCodeLength)
	rand.Read(b)
	
	code := make([]byte, InviteCodeLength)
	for i := 0; i < InviteCodeLength; i++ {
		code[i] = InviteCodeChars[int(b[i])%len(InviteCodeChars)]
	}
	return string(code)
}

func (s *RelayServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Limit request body size to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.APIKey != s.apiKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if req.CACert == "" || req.CAKey == "" {
		http.Error(w, "Missing CA certificate or key", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var inviteCode string
	for {
		inviteCode = generateInviteCode()
		if _, exists := s.networks[inviteCode]; !exists {
			break
		}
	}

	network := &NetworkInfo{
		InviteCode: inviteCode,
		CACert:     req.CACert,
		CAKey:      req.CAKey,
		RelayIP:    fmt.Sprintf("%s:%d", s.relayIP, RelayUDPPort),
		HostIP:     HostIP,
		Subnet:     NetworkSubnet,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	s.networks[inviteCode] = network

	log.Printf("Registered network: %s (expires: %s)", inviteCode, network.ExpiresAt.Format(time.RFC3339))

	resp := RegisterResponse{
		InviteCode: inviteCode,
		HostIP:     HostIP,
		Subnet:     NetworkSubnet,
		RelayIP:    network.RelayIP,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *RelayServer) handleInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	vars := mux.Vars(r)
	inviteCode := strings.ToUpper(vars["code"])
	
	// Validate invite code format
	if len(inviteCode) != InviteCodeLength {
		http.Error(w, "Invalid invite code format", http.StatusBadRequest)
		return
	}
	
	// Check for valid characters only
	for _, char := range inviteCode {
		if !strings.ContainsRune(InviteCodeChars, char) {
			http.Error(w, "Invalid invite code characters", http.StatusBadRequest)
			return
		}
	}

	s.mu.RLock()
	network, exists := s.networks[inviteCode]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Invite code not found", http.StatusNotFound)
		return
	}

	if time.Now().After(network.ExpiresAt) {
		s.mu.Lock()
		delete(s.networks, inviteCode)
		s.mu.Unlock()
		http.Error(w, "Invite code expired", http.StatusGone)
		return
	}

	resp := InviteResponse{
		CACert:  network.CACert,
		CAKey:   network.CAKey,
		RelayIP: network.RelayIP,
		HostIP:  network.HostIP,
		Subnet:  network.Subnet,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *RelayServer) handleUnregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Limit request body size to 1KB (unregister is small)
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	
	var req UnregisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.APIKey != s.apiKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	inviteCode := strings.ToUpper(req.InviteCode)
	if _, exists := s.networks[inviteCode]; !exists {
		http.Error(w, "Invite code not found", http.StatusNotFound)
		return
	}

	delete(s.networks, inviteCode)
	log.Printf("Unregistered network: %s", inviteCode)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *RelayServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	count := len(s.networks)
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"networks": count,
		"uptime":   time.Since(startTime).String(),
	})
}

func (s *RelayServer) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		expired := []string{}
		
		for code, network := range s.networks {
			if now.After(network.ExpiresAt) {
				expired = append(expired, code)
			}
		}
		
		for _, code := range expired {
			delete(s.networks, code)
			log.Printf("Expired network: %s", code)
		}
		s.mu.Unlock()
	}
}

var startTime = time.Now()

func generateAPIKey() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const length = 32
	
	key := make([]byte, length)
	for i := 0; i < length; i++ {
		// Use crypto/rand for unbiased selection
		b := make([]byte, 1)
		rand.Read(b)
		key[i] = chars[b[0]%byte(len(chars))]
	}
	return string(key)
}

func getAPIKey(staticKey string) string {
	if staticKey != "" {
		log.Printf("Using provided API key")
		return staticKey
	}
	
	key := generateAPIKey()
	log.Printf("Generated random API key")
	return key
}

func generateSelfSignedCert() (*tls.Certificate, error) {
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{Organization: []string{"Nebula Relay"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func main() {
	// Parse command-line arguments
	relayIP := flag.String("ip", "", "Public IP address of this relay server (required)")
	httpPort := flag.Int("port", RelayHTTPPort, "HTTPS API port")
	apiKey := flag.String("key", "", "Static API key (optional, generates random if not provided)")
	flag.Parse()
	
	if *relayIP == "" {
		log.Fatal("Error: -ip flag is required (public IP address of this server)")
	}
	
	// Get or generate API key
	finalAPIKey := getAPIKey(*apiKey)
	
	log.Printf("API Key: %s", finalAPIKey)
	log.Printf("Share this key with hosts who need to register networks")

	// Generate self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatal("Failed to generate certificate:", err)
	}

	// Create server
	server := NewRelayServer(finalAPIKey, *relayIP)

	// Start cleanup goroutine
	go server.cleanupExpired()

	// Setup routes
	r := mux.NewRouter()
	r.HandleFunc("/api/register", server.handleRegister).Methods("POST")
	r.HandleFunc("/api/invite/{code}", server.handleInvite).Methods("GET")
	r.HandleFunc("/api/unregister", server.handleUnregister).Methods("DELETE")
	r.HandleFunc("/api/status", server.handleStatus).Methods("GET")

	// Create HTTPS server
	addr := fmt.Sprintf(":%d", *httpPort)
	httpsServer := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
		},
	}

	log.Printf("Relay server starting on %s (HTTPS)", addr)
	log.Printf("Nebula lighthouse should be running on UDP %d", RelayUDPPort)
	log.Printf("Public IP: %s", *relayIP)
	log.Printf("⚠️  Using self-signed certificate - clients will need to accept certificate warning")
	
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

