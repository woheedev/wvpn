package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/color"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Embed binaries at build time
//go:embed binaries/wintun.dll
var wintunDLL []byte

//go:embed binaries/nebula.exe
var nebulaBinary []byte

//go:embed binaries/nebula-cert.exe
var nebulaCertBinary []byte

// Global paths to extracted binaries
var (
	tempDir        string
	wintunPath     string
	nebulaPath     string
	nebulaCertPath string
	configDir      string // Directory for Nebula config and certs (set based on mode)
	baseDir        string // Base directory for the application
)

// InviteCode structure for joining networks
type InviteCode struct {
	HostIP    string `json:"h"` // Host lighthouse IP (e.g., "127.0.0.1:4242" for local testing)
	CACert    string `json:"c"` // Base64 encoded CA certificate
	CAKey     string `json:"k"` // Base64 encoded CA key (INSECURE - for local testing only)
	NetworkIP string `json:"n"` // Network range (e.g., "100.200.0.0/24")
}

// Service represents an exposed port/application
type Service struct {
	Name string // User-friendly name (e.g., "Minecraft Server")
	Port int    // Port number (e.g., 25565)
	Proto string // Protocol: "tcp" or "udp"
}

// Client represents a connected client
type Client struct {
	Name      string    // Device name
	IP        string    // Nebula IP (e.g., "100.200.0.5")
	Status    string    // "pending" or "approved"
	ConnTime  time.Time // Connection time
	Conn      net.Conn  // TCP connection for control messages
}

// ControlMessage for host-client communication
type ControlMessage struct {
	Type string `json:"type"` // "register", "approve", "kick", "heartbeat"
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
}

// ClientManager handles client connections
type ClientManager struct {
	clients map[string]*Client // Key: client IP
	mu      sync.RWMutex
	addLog  func(string)
}

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

type AppState struct {
	mode           string         // "", "host", or "join"
	showLogs       bool           // Toggle for logs display
	showClients    bool           // Clients window open state
	editingDevice  bool           // Device name editing mode
	deviceName     string         // Current device name (max 16 chars)
	inviteCode     string         // Current invite code (base64 encoded JSON)
	clientIP       string         // Assigned client IP (for join mode)
	isConnected    bool           // True when Nebula is running (host or client)
	isApproved     bool           // True when host approves client (client only)
	services       []Service      // Exposed services/ports (host only)
	clientManager  *ClientManager // Manages connected clients (host only)
	controlServer  net.Listener   // Control server listener (host only)
	controlClient  net.Conn       // Control connection to host (client only)
	clientsWindow  fyne.Window    // Reference to clients popup window
	settingsWindow fyne.Window    // Reference to settings popup window
	nebulaProc     *os.Process    // Running Nebula process
	kickedByHost   bool           // True if client was kicked by host
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================

func main() {
	// Extract embedded binaries to temp directory on startup
	if err := extractBinaries(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to extract binaries: %v\n", err)
		os.Exit(1)
	}

	// Cleanup temp directory on exit
	defer cleanupTempDir()

	myApp := app.New()
	myWindow := myApp.NewWindow("Nebula VPN")

	// Initialize application state
	state := &AppState{
		mode:           "",
		showLogs:       false,
		showClients:    false,
		editingDevice:  false,
		deviceName:     getHostname(),
		inviteCode:     "", // Will be generated when host mode starts
		clientIP:       "", // Will be assigned when joining
		isConnected:    false,
		isApproved:     false,
		services:       []Service{}, // Empty services list
		clientManager:  nil, // Will be created in host mode
		controlServer:  nil,
		controlClient:  nil,
		clientsWindow:  nil,
		settingsWindow: nil,
		kickedByHost:   false,
	}

	// UI containers
	modeContent := container.NewVBox()
	logsContainer := container.NewVBox()

	// Status label (italic styling for visual separation)
	statusLabel := widget.NewLabel("Ready")
	statusLabel.TextStyle = fyne.TextStyle{Italic: true}

	// Logs display (disabled for read-only)
	logsDisplay := widget.NewEntry()
	logsDisplay.SetPlaceHolder("Logs will appear here...")
	logsDisplay.MultiLine = true
	logsDisplay.Wrapping = fyne.TextWrapWord
	logsDisplay.Disable()

	// Helper: Add timestamped log entry (latest at top) - thread-safe
	addLog := func(message string) {
		now := time.Now()
		timestamp := fmt.Sprintf("%02d:%02d:%02d.%03d", now.Hour(), now.Minute(), now.Second(), now.Nanosecond()/1000000)
		logEntry := fmt.Sprintf("[%s] %s", timestamp, message)
		
		// Must update UI from main thread
		fyne.Do(func() {
			if logsDisplay.Text == "" {
				logsDisplay.SetText(logEntry)
			} else {
				logsDisplay.SetText(logEntry + "\n" + logsDisplay.Text)
			}
		})
	}

	// Helper: Set status and add to logs - thread-safe
	setStatus := func(message string) {
		fyne.Do(func() {
			statusLabel.SetText(message)
		})
		addLog(message)
	}

	// Main content update function (only updates middle section)
	var updateContent func()
	updateContent = func() {
		modeContent.Objects = modeContent.Objects[:0]
		logsContainer.Objects = logsContainer.Objects[:0]

		// Add logs if expanded
		if state.showLogs {
			logsContainer.Objects = append(logsContainer.Objects, logsDisplay)
		}

		// Mode-specific content and calculate window height
		var height float32
		switch state.mode {
		case "":
			modeContent.Objects = append(modeContent.Objects, buildModeSelection(state, updateContent, setStatus, addLog))
			height = 150
		case "host":
			modeContent.Objects = append(modeContent.Objects, buildHostView(state, updateContent, setStatus, addLog, myWindow, myApp))
			height = 250
		case "join":
			modeContent.Objects = append(modeContent.Objects, buildJoinView(state, updateContent, setStatus, addLog, myWindow))
			height = 200
		}

		// Add logs height if shown
		if state.showLogs {
			height += 100
		}

		myWindow.Resize(fyne.NewSize(300, height))
	}

	// Device name section (built once, updates when editing)
	var deviceNameContainer *fyne.Container
	var updateDeviceName func()
	updateDeviceName = func() {
		deviceWidget := buildDeviceNameWidget(state, func() {
			updateDeviceName()
			updateContent()
		}, setStatus, myApp)
		if deviceNameContainer == nil {
			deviceNameContainer = container.NewVBox(deviceWidget, newWhiteSeparator())
		} else {
			deviceNameContainer.Objects = []fyne.CanvasObject{deviceWidget, newWhiteSeparator()}
			deviceNameContainer.Refresh()
		}
	}
	updateDeviceName()

	// Logs toggle button
	logsToggleBtn := widget.NewButtonWithIcon("", theme.MenuDropDownIcon(), func() {
		state.showLogs = !state.showLogs
		updateContent()
	})
	logsToggleBtn.Importance = widget.LowImportance

	// Bottom status bar (built once)
	bottomBar := container.NewBorder(
		newWhiteSeparator(),
		logsContainer,
		nil,
		logsToggleBtn,
		statusLabel,
	)

	// Assemble layout: device name (top) -> mode content (middle) -> status bar (bottom)
	mainLayout := container.NewBorder(deviceNameContainer, bottomBar, nil, nil, modeContent)

	myWindow.SetContent(mainLayout)
	updateContent()
	myWindow.SetFixedSize(true)
	
	// Cleanup Nebula when window closes
	myWindow.SetOnClosed(func() {
		if state.nebulaProc != nil {
			state.nebulaProc.Kill()
		}
	})
	
	myWindow.ShowAndRun()
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func newWhiteSeparator() *canvas.Rectangle {
	line := canvas.NewRectangle(color.White)
	line.SetMinSize(fyne.NewSize(0, 1))
	return line
}

func getHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "MyDevice"
	}
	if len(name) > 16 {
		return name[:16]
	}
	return name
}

// Generate invite code from CA certificate
// Note: Includes CA private key for easy client cert generation.
// Suitable for temporary gaming sessions (24h cert expiration).
// New CA generated each time host starts, so old invite codes become invalid.
func generateInviteCode() (string, error) {
	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")
	
	caCertData, err := os.ReadFile(caCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to read CA cert: %w", err)
	}
	
	caKeyData, err := os.ReadFile(caKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read CA key: %w", err)
	}

	invite := InviteCode{
		HostIP:    "127.0.0.1:4242", // For local testing, use localhost
		CACert:    base64.StdEncoding.EncodeToString(caCertData),
		CAKey:     base64.StdEncoding.EncodeToString(caKeyData),
		NetworkIP: "100.200.0.0/24",
	}

	jsonData, err := json.Marshal(invite)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invite: %w", err)
	}

	return base64.StdEncoding.EncodeToString(jsonData), nil
}

// Parse invite code
func parseInviteCode(code string) (*InviteCode, error) {
	jsonData, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return nil, fmt.Errorf("invalid invite code format: %w", err)
	}

	var invite InviteCode
	if err := json.Unmarshal(jsonData, &invite); err != nil {
		return nil, fmt.Errorf("invalid invite code data: %w", err)
	}

	return &invite, nil
}

// ============================================================================
// CLIENT MANAGER
// ============================================================================

// NewClientManager creates a new client manager
func NewClientManager(addLog func(string)) *ClientManager {
	return &ClientManager{
		clients: make(map[string]*Client),
		addLog:  addLog,
	}
}

// AddClient adds a new client (or updates connection for existing client)
func (cm *ClientManager) AddClient(name, ip string, conn net.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Check if client already exists (e.g., reconnecting after Nebula restart)
	if existingClient, exists := cm.clients[ip]; exists {
		// Update connection but preserve approval status
		existingClient.Conn = conn
		existingClient.ConnTime = time.Now()
		existingClient.Name = name // Update name in case it changed
		cm.addLog(fmt.Sprintf("Client reconnected: %s (%s) - status: %s", name, ip, existingClient.Status))
		return
	}
	
	// New client - add as pending
	cm.clients[ip] = &Client{
		Name:     name,
		IP:       ip,
		Status:   "pending",
		ConnTime: time.Now(),
		Conn:     conn,
	}
	cm.addLog(fmt.Sprintf("New client pending: %s (%s)", name, ip))
}

// ApproveClient approves a pending client
func (cm *ClientManager) ApproveClient(ip string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if client, ok := cm.clients[ip]; ok {
		client.Status = "approved"
		cm.addLog(fmt.Sprintf("Client approved: %s (%s)", client.Name, ip))
		
		// Send approve message (if connected)
		if client.Conn != nil {
			msg := ControlMessage{Type: "approve"}
			json.NewEncoder(client.Conn).Encode(msg)
		}
		return true
	}
	return false
}

// KickClient kicks a client
func (cm *ClientManager) KickClient(ip string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if client, ok := cm.clients[ip]; ok {
		cm.addLog(fmt.Sprintf("Kicking client: %s (%s)", client.Name, ip))
		
		// Send kick message (if connected)
		if client.Conn != nil {
			msg := ControlMessage{Type: "kick"}
			json.NewEncoder(client.Conn).Encode(msg)
			client.Conn.Close()
		}
		
		// Remove from manager
		delete(cm.clients, ip)
	}
}

// GetClients returns a copy of all clients
func (cm *ClientManager) GetClients() []*Client {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	clients := make([]*Client, 0, len(cm.clients))
	for _, client := range cm.clients {
		clients = append(clients, client)
	}
	return clients
}

// GetApprovedClients returns a copy of approved clients only
func (cm *ClientManager) GetApprovedClients() []*Client {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	clients := make([]*Client, 0)
	for _, client := range cm.clients {
		if client.Status == "approved" {
			clients = append(clients, client)
		}
	}
	return clients
}

// RemoveClient removes a client only if not approved (preserves approved clients across reconnects)
func (cm *ClientManager) RemoveClient(ip string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if client, ok := cm.clients[ip]; ok {
		// Don't remove approved clients (they might be reconnecting after Nebula restart)
		if client.Status == "approved" {
			cm.addLog(fmt.Sprintf("Approved client disconnected (keeping for reconnect): %s (%s)", client.Name, ip))
			if client.Conn != nil {
				client.Conn.Close() // Close old connection
				client.Conn = nil   // Mark as disconnected
			}
			return
		}
		
		// Remove pending clients on disconnect
		cm.addLog(fmt.Sprintf("Pending client disconnected: %s (%s)", client.Name, ip))
		if client.Conn != nil {
			client.Conn.Close()
		}
		delete(cm.clients, ip)
	}
}

// ============================================================================
// BINARY EXTRACTION
// ============================================================================

// Extract embedded binaries to fixed directory (avoids Windows Firewall prompts)
func extractBinaries() error {
	// Use fixed directory in LocalAppData (avoids firewall prompts on every run)
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		// Fallback to APPDATA if LOCALAPPDATA not set
		localAppData = os.Getenv("APPDATA")
	}
	if localAppData == "" {
		return fmt.Errorf("failed to determine AppData directory")
	}
	
	baseDir = filepath.Join(localAppData, "NebulaVPN")
	tempDir = baseDir // For compatibility
	
	// Create main directory
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("failed to create app directory: %w", err)
	}

	// Note: configDir will be set based on mode (host/client) to avoid conflicts

	// Create wintun directory structure that Nebula expects
	// Nebula looks for: dist/windows/wintun/bin/amd64/wintun.dll
	wintunDir := filepath.Join(baseDir, "dist", "windows", "wintun", "bin", "amd64")
	if err := os.MkdirAll(wintunDir, 0755); err != nil {
		return fmt.Errorf("failed to create wintun directory: %w", err)
	}

	// Extract wintun.dll to the expected location
	wintunPath = filepath.Join(wintunDir, "wintun.dll")
	if err := writeFile(wintunPath, wintunDLL); err != nil {
		return fmt.Errorf("failed to extract wintun.dll: %w", err)
	}

	// Extract nebula.exe
	nebulaPath = filepath.Join(baseDir, "nebula.exe")
	if err := writeFile(nebulaPath, nebulaBinary); err != nil {
		return fmt.Errorf("failed to extract nebula.exe: %w", err)
	}

	// Extract nebula-cert.exe
	nebulaCertPath = filepath.Join(baseDir, "nebula-cert.exe")
	if err := writeFile(nebulaCertPath, nebulaCertBinary); err != nil {
		return fmt.Errorf("failed to extract nebula-cert.exe: %w", err)
	}

	return nil
}

// Write embedded binary data to file
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0755)
}

// Cleanup function (kept for future use, but not deleting persistent directory)
func cleanupTempDir() {
	// Note: We no longer delete baseDir on exit to:
	// 1. Avoid Windows Firewall prompts (same exe path every run)
	// 2. Persist binaries (no re-extraction on every start)
	// Config directories are mode-specific (host/client) to allow testing both simultaneously
	// Directory: %LOCALAPPDATA%\NebulaVPN\
}

// Set config directory based on mode (host or client)
// This allows running host and client on the same machine for testing
func setConfigDir(mode string) error {
	if baseDir == "" {
		return fmt.Errorf("base directory not initialized")
	}
	
	configDir = filepath.Join(baseDir, mode, "config")
	
	// Create config directory
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	return nil
}

// ============================================================================
// NEBULA CERTIFICATE MANAGEMENT
// ============================================================================

// Generate CA certificate for host (fresh CA for each session)
func generateCA(addLog func(string)) error {
	caName := "nebula-mesh-ca"
	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")
	
	// Clean up old CA if it exists (fresh CA for each session)
	os.Remove(caCertPath)
	os.Remove(caKeyPath)
	
	addLog("Generating new CA certificate for this session...")
	
	// Run: nebula-cert ca -name "nebula-mesh-ca" -duration 24h
	cmd := exec.Command(nebulaCertPath, "ca", 
		"-name", caName, 
		"-duration", "24h", // Expire in 24 hours
		"-out-crt", caCertPath, 
		"-out-key", caKeyPath)
	cmd.Dir = configDir
	
	// Hide console window on Windows
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		addLog(fmt.Sprintf("CA generation failed: %s", string(output)))
		return fmt.Errorf("failed to generate CA: %w\nOutput: %s", err, string(output))
	}
	
	addLog("CA certificate generated (expires in 24 hours)")
	return nil
}

// Generate host certificate (fresh for each session)
func generateHostCert(deviceName string, addLog func(string)) error {
	hostCertPath := filepath.Join(configDir, "host.crt")
	hostKeyPath := filepath.Join(configDir, "host.key")
	
	// Clean up old host cert (fresh cert for each session)
	os.Remove(hostCertPath)
	os.Remove(hostKeyPath)
	
	addLog(fmt.Sprintf("Generating certificate for %s...", deviceName))
	
	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")
	
	// Run: nebula-cert sign -name "deviceName" -ip "100.200.0.1/24" -duration 12h
	// Note: Signed cert must expire BEFORE the CA (CA is 24h, so we use 12h for safety margin)
	cmd := exec.Command(nebulaCertPath, "sign",
		"-name", deviceName,
		"-ip", "100.200.0.1/24",
		"-duration", "12h", // Half of CA duration for safety margin
		"-ca-crt", caCertPath,
		"-ca-key", caKeyPath,
		"-out-crt", hostCertPath,
		"-out-key", hostKeyPath,
	)
	cmd.Dir = configDir
	
	// Hide console window on Windows
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		addLog(fmt.Sprintf("Certificate generation failed: %s", string(output)))
		return fmt.Errorf("failed to generate host certificate: %w\nOutput: %s", err, string(output))
	}
	
	addLog("Host certificate generated: 100.200.0.1 (expires in 12h)")
	return nil
}

// ============================================================================
// NEBULA CONFIGURATION
// ============================================================================

// Create Nebula config file for host
func createHostConfig(addLog func(string)) error {
	return createHostConfigWithServices(nil, nil, addLog)
}

// Create Nebula config file for host with service firewall rules
func createHostConfigWithServices(services []Service, clientManager *ClientManager, addLog func(string)) error {
	addLog("Creating Nebula configuration...")
	
	configPath := filepath.Join(configDir, "config.yml")
	caCertPath := filepath.Join(configDir, "ca.crt")
	hostCertPath := filepath.Join(configDir, "host.crt")
	hostKeyPath := filepath.Join(configDir, "host.key")
	
	// Base config
	config := fmt.Sprintf(`pki:
  ca: %s
  cert: %s
  key: %s

static_host_map:
  "100.200.0.1": []

lighthouse:
  am_lighthouse: true
  interval: 60

listen:
  host: 0.0.0.0
  port: 4242

punchy:
  punch: true
  respond: true

tun:
  disabled: false
  dev: nebula-host
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300

firewall:
  outbound_action: drop
  inbound_action: drop
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m

  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    # Control server (required for client approval)
    - port: 9999
      proto: tcp
      host: any
`, caCertPath, hostCertPath, hostKeyPath)
	
	// Add firewall rules for approved clients and services
	if len(services) > 0 && clientManager != nil {
		approvedClients := clientManager.GetApprovedClients()
		
		for _, service := range services {
			for _, client := range approvedClients {
				// Add rule for each approved client to access each service
				rule := fmt.Sprintf(`
    - port: %d
      proto: %s
      host: "%s"`, service.Port, service.Proto, client.IP)
				config += rule
			}
		}
	}
	
	// Close config
	config += `

logging:
  level: info
  format: text
`
	
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	addLog("Configuration file created")
	return nil
}

// Generate client certificate (assigns random IP for each session)
func generateClientCert(deviceName string, invite *InviteCode, addLog func(string)) (string, error) {
	clientCertPath := filepath.Join(configDir, "client.crt")
	clientKeyPath := filepath.Join(configDir, "client.key")
	
	// Clean up old client cert (fresh cert for each join)
	os.Remove(clientCertPath)
	os.Remove(clientKeyPath)
	
	// Assign a random client IP (100.200.0.2-254)
	rand.Seed(time.Now().UnixNano())
	clientIPNum := rand.Intn(253) + 2 // 2-254
	clientIP := fmt.Sprintf("100.200.0.%d", clientIPNum)
	clientIPWithMask := fmt.Sprintf("%s/24", clientIP)
	
	addLog(fmt.Sprintf("Generating client certificate for %s...", deviceName))
	
	// Decode CA cert and key from invite
	caCertData, err := base64.StdEncoding.DecodeString(invite.CACert)
	if err != nil {
		return "", fmt.Errorf("failed to decode CA cert: %w", err)
	}
	
	caKeyData, err := base64.StdEncoding.DecodeString(invite.CAKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode CA key: %w", err)
	}
	
	// Write CA cert and key to config dir
	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")
	
	if err := os.WriteFile(caCertPath, caCertData, 0644); err != nil {
		return "", fmt.Errorf("failed to write CA cert: %w", err)
	}
	
	if err := os.WriteFile(caKeyPath, caKeyData, 0600); err != nil {
		return "", fmt.Errorf("failed to write CA key: %w", err)
	}
	
	addLog(fmt.Sprintf("Assigned IP: %s", clientIP))
	
	// Generate client certificate using nebula-cert (12h expiration)
	// Note: Signed cert must expire BEFORE the CA (CA is 24h, so we use 12h for safety margin)
	cmd := exec.Command(nebulaCertPath, "sign",
		"-name", deviceName,
		"-ip", clientIPWithMask,
		"-duration", "12h", // Half of CA duration for safety margin
		"-ca-crt", caCertPath,
		"-ca-key", caKeyPath,
		"-out-crt", clientCertPath,
		"-out-key", clientKeyPath,
	)
	cmd.Dir = configDir
	
	// Hide console window
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		addLog(fmt.Sprintf("Certificate generation failed: %s", string(output)))
		return "", fmt.Errorf("failed to generate client certificate: %w", err)
	}
	
	addLog(fmt.Sprintf("Client certificate generated: %s (expires in 12h)", clientIP))
	return clientIPWithMask, nil
}

// Create Nebula config file for client
func createClientConfig(clientIP, deviceName string, invite *InviteCode, addLog func(string)) error {
	addLog("Creating client configuration...")
	
	configPath := filepath.Join(configDir, "config.yml")
	caCertPath := filepath.Join(configDir, "ca.crt")
	clientCertPath := filepath.Join(configDir, "client.crt")
	clientKeyPath := filepath.Join(configDir, "client.key")
	
	config := fmt.Sprintf(`pki:
  ca: %s
  cert: %s
  key: %s

static_host_map:
  "100.200.0.1": ["%s"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "100.200.0.1"

listen:
  host: 0.0.0.0
  port: 0

punchy:
  punch: true
  respond: true

tun:
  disabled: false
  dev: nebula-client
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300

firewall:
  outbound_action: drop
  inbound_action: drop
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m

  outbound:
    # Unapproved clients: Only control server access
    - port: 9999
      proto: tcp
      host: "100.200.0.1"
    
    # TODO: Approved clients will get additional rules here

  inbound:
    # Host can always reach client
    - port: any
      proto: any
      host: "100.200.0.1"

logging:
  level: info
  format: text
`, caCertPath, clientCertPath, clientKeyPath, invite.HostIP)
	
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	addLog("Configuration file created")
	return nil
}

// ============================================================================
// NEBULA PROCESS MANAGEMENT
// ============================================================================

// Start Nebula as host
func startNebulaHost(state *AppState, addLog func(string)) error {
	addLog("Starting Nebula...")
	
	configPath := filepath.Join(configDir, "config.yml")
	
	cmd := exec.Command(nebulaPath, "-config", configPath)
	cmd.Dir = tempDir
	
	// Hide console window on Windows
	// Combine CREATE_NO_WINDOW and DETACHED_PROCESS for maximum hiding
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000 | 0x00000008, // CREATE_NO_WINDOW | DETACHED_PROCESS
	}
	
	// Capture stdout/stderr for logging
	cmd.Stdout = &nebulaLogger{addLog: addLog, prefix: "[nebula]"}
	cmd.Stderr = &nebulaLogger{addLog: addLog, prefix: "[nebula]"}
	
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Nebula: %w", err)
	}
	
	state.nebulaProc = cmd.Process
	state.isConnected = true
	addLog(fmt.Sprintf("Nebula started (PID: %d)", cmd.Process.Pid))
	addLog("Host is now running on 100.200.0.1")
	
	// Monitor process in background
	go func() {
		cmd.Wait()
		addLog("Nebula process exited")
		state.nebulaProc = nil
		state.isConnected = false
	}()
	
	return nil
}

// Stop Nebula process
func stopNebula(state *AppState, addLog func(string)) {
	if state.nebulaProc != nil {
		addLog("Stopping Nebula...")
		state.nebulaProc.Kill()
		state.nebulaProc = nil
		state.isConnected = false
		addLog("Nebula stopped")
	}
}

// Restart Nebula (used when updating firewall rules)
func restartNebula(state *AppState, addLog func(string)) error {
	addLog("Restarting Nebula to apply new firewall rules...")
	
	// Stop current instance
	if state.nebulaProc != nil {
		state.nebulaProc.Kill()
		state.nebulaProc = nil
		time.Sleep(1 * time.Second) // Wait for clean shutdown
	}
	
	// Regenerate config with updated firewall rules
	if err := createHostConfigWithServices(state.services, state.clientManager, addLog); err != nil {
		return fmt.Errorf("failed to regenerate config: %w", err)
	}
	
	// Restart Nebula
	if err := startNebulaHost(state, addLog); err != nil {
		return fmt.Errorf("failed to restart Nebula: %w", err)
	}
	
	// Restart control server
	if state.controlServer != nil {
		state.controlServer.Close()
		time.Sleep(500 * time.Millisecond)
	}
	
	if err := startControlServer(state, addLog); err != nil {
		addLog("Warning: Failed to restart control server: " + err.Error())
	}
	
	addLog("Nebula restarted successfully")
	return nil
}

// ============================================================================
// CONTROL PROTOCOL (CLIENT TRACKING)
// ============================================================================

// Start control server on host (port 9999 on Nebula network)
func startControlServer(state *AppState, addLog func(string)) error {
	addLog("Starting control server on 100.200.0.1:9999...")
	
	listener, err := net.Listen("tcp", "100.200.0.1:9999")
	if err != nil {
		return fmt.Errorf("failed to start control server: %w", err)
	}
	
	state.controlServer = listener
	
	// Only create ClientManager if it doesn't exist (preserve approval states on restart)
	if state.clientManager == nil {
		state.clientManager = NewClientManager(addLog)
	}
	
	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Server closed
				return
			}
			
			// Handle client in background
			go handleControlClient(conn, state, addLog)
		}
	}()
	
	addLog("Control server started")
	return nil
}

// Handle a control client connection
func handleControlClient(conn net.Conn, state *AppState, addLog func(string)) {
	defer conn.Close()
	
	decoder := json.NewDecoder(conn)
	var msg ControlMessage
	
	// Read registration message
	if err := decoder.Decode(&msg); err != nil {
		return
	}
	
	if msg.Type == "register" {
		clientIP := msg.IP // Save IP for cleanup
		
		// Add client (or update if reconnecting)
		state.clientManager.AddClient(msg.Name, clientIP, conn)
		
		// If client is already approved (reconnecting after restart), send approve message
		state.clientManager.mu.RLock()
		client, exists := state.clientManager.clients[clientIP]
		isApproved := exists && client.Status == "approved"
		state.clientManager.mu.RUnlock()
		
		if isApproved {
			// Send approval message immediately for reconnected approved clients
			approveMsg := ControlMessage{Type: "approve"}
			json.NewEncoder(conn).Encode(approveMsg)
		}
		
		// Keep connection open for future messages
		for {
			if err := decoder.Decode(&msg); err != nil {
				// Client disconnected
				state.clientManager.RemoveClient(clientIP)
				return
			}
			
			// Handle heartbeat or other messages
			if msg.Type == "heartbeat" {
				// Client is still alive
			}
		}
	}
}

// Stop control server
func stopControlServer(state *AppState, addLog func(string)) {
	if state.controlServer != nil {
		addLog("Stopping control server...")
		state.controlServer.Close()
		state.controlServer = nil
		state.clientManager = nil
	}
}

// Connect to control server (client) with auto-reconnect
func connectToControlServer(state *AppState, hostIP string, addLog func(string), updateContent func()) error {
	addLog(fmt.Sprintf("Connecting to control server at %s:9999...", hostIP))
	
	// Initial connection
	if err := attemptControlConnection(state, hostIP, addLog, updateContent); err != nil {
		return err
	}
	
	// Auto-reconnect goroutine
	go func() {
		for {
			time.Sleep(5 * time.Second)
			
			// Check if still in join mode and not kicked
			if state.mode != "join" || state.kickedByHost || !state.isConnected {
				return // Stop auto-reconnect
			}
			
			// Check if connection is alive
			if state.controlClient == nil {
				addLog("Control server disconnected, attempting to reconnect...")
				
				// Try to reconnect
				for i := 0; i < 3; i++ {
					if err := attemptControlConnection(state, hostIP, addLog, updateContent); err == nil {
						addLog("✅ Reconnected to control server")
						break
					}
					time.Sleep(2 * time.Second)
				}
			}
		}
	}()
	
	return nil
}

// Attempt a single connection to control server
func attemptControlConnection(state *AppState, hostIP string, addLog func(string), updateContent func()) error {
	// Try to connect with timeout
	conn, err := net.DialTimeout("tcp", hostIP+":9999", 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to host control server: %w", err)
	}
	
	state.controlClient = conn
	
	// Send registration
	msg := ControlMessage{
		Type: "register",
		Name: state.deviceName,
		IP:   strings.Split(state.clientIP, "/")[0], // Remove /24 mask
	}
	
	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		conn.Close()
		state.controlClient = nil
		return fmt.Errorf("failed to register with host: %w", err)
	}
	
	// Only log registration on first connect or explicit reconnect
	if !state.isApproved {
		addLog("Registered with host, awaiting approval...")
	}
	
	// Listen for messages from host in background
	go func() {
		decoder := json.NewDecoder(conn)
		for {
			var msg ControlMessage
			if err := decoder.Decode(&msg); err != nil {
				// Connection lost
				state.controlClient = nil
				
				// Only show error if we were kicked (intentional disconnect)
				if state.kickedByHost {
					addLog("Connection to host closed")
				}
				
				return
			}
			
			switch msg.Type {
			case "approve":
				if !state.isApproved {
					state.isApproved = true
					addLog("✅ Host approved your connection!")
					// Update UI to show approved status
					fyne.Do(func() {
						updateContent()
					})
				}
			case "kick":
				addLog("You have been kicked by the host")
				state.kickedByHost = true
				state.controlClient = nil
				stopNebula(state, addLog)
				fyne.Do(func() {
					updateContent()
				})
				return
			}
		}
	}()
	
	return nil
}

// Disconnect from control server (client)
func disconnectFromControlServer(state *AppState) {
	if state.controlClient != nil {
		state.controlClient.Close()
		state.controlClient = nil
	}
}

// Validate host is reachable before joining
func validateHostConnection(hostIP string) error {
	// Try to dial the Nebula lighthouse port with timeout
	conn, err := net.DialTimeout("tcp", hostIP, 2*time.Second)
	if err != nil {
		return fmt.Errorf("host not reachable: %w", err)
	}
	conn.Close()
	return nil
}

// Custom writer for Nebula logs
type nebulaLogger struct {
	addLog func(string)
	prefix string
	buffer string
}

func (nl *nebulaLogger) Write(p []byte) (n int, err error) {
	nl.buffer += string(p)
	
	// Process complete lines
	for {
		idx := strings.Index(nl.buffer, "\n")
		if idx == -1 {
			break
		}
		
		line := strings.TrimSpace(nl.buffer[:idx])
		if line != "" {
			nl.addLog(nl.prefix + " " + line)
		}
		nl.buffer = nl.buffer[idx+1:]
	}
	
	return len(p), nil
}

// ============================================================================
// UI BUILDERS
// ============================================================================

func buildModeSelection(state *AppState, updateContent func(), setStatus func(string), addLog func(string)) fyne.CanvasObject {
	// HOST button
	hostBtn := widget.NewButton("HOST", func() {
		state.mode = "host"
		setStatus("Starting host mode...")
		updateContent()
		
		// Start Nebula hosting in background
		go func() {
			// Set config directory for host mode
			if err := setConfigDir("host"); err != nil {
				setStatus("Failed to initialize host directory: " + err.Error())
				return
			}
			
			// Generate CA certificate
			if err := generateCA(addLog); err != nil {
				setStatus("Failed to generate CA: " + err.Error())
				return
			}
			
			// Generate host certificate
			if err := generateHostCert(state.deviceName, addLog); err != nil {
				setStatus("Failed to generate certificate: " + err.Error())
				return
			}
			
			// Create config file
			if err := createHostConfig(addLog); err != nil {
				setStatus("Failed to create config: " + err.Error())
				return
			}
			
			// Start Nebula
			if err := startNebulaHost(state, addLog); err != nil {
				setStatus("Failed to start Nebula: " + err.Error())
				return
			}
			
			// Wait a moment for Nebula interface to be ready
			time.Sleep(2 * time.Second)
			
			// Start control server for client tracking
			if err := startControlServer(state, addLog); err != nil {
				addLog("Warning: Failed to start control server: " + err.Error())
			}
			
			// Generate invite code
			code, err := generateInviteCode()
			if err != nil {
				addLog("Warning: Failed to generate invite code: " + err.Error())
			} else {
				state.inviteCode = code
				addLog("Invite code generated")
			}
			
			setStatus("Hosting active on 100.200.0.1")
		}()
	})
	hostBtn.Importance = widget.HighImportance

	// JOIN button
	joinBtn := widget.NewButton("JOIN", func() {
		state.mode = "join"
		setStatus("Join mode selected")
		updateContent()
	})

	buttons := container.NewGridWithColumns(2, hostBtn, joinBtn)

	return container.NewVBox(
		buttons,
	)
}

func buildHostView(state *AppState, updateContent func(), setStatus func(string), addLog func(string), window fyne.Window, app fyne.App) fyne.CanvasObject {
	// Invite code display (read-only)
	inviteCodeEntry := widget.NewEntry()
	inviteCodeEntry.SetText(state.inviteCode)
	inviteCodeEntry.Disable()

	// Copy invite code to clipboard
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		window.Clipboard().SetContent(state.inviteCode)
		setStatus("Invite code copied to clipboard")
	})

	// Regenerate invite code
	refreshBtn := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() {
		code, err := generateInviteCode()
		if err != nil {
			setStatus("Failed to generate invite code: " + err.Error())
			return
		}
		state.inviteCode = code
		inviteCodeEntry.SetText(state.inviteCode)
		setStatus("New invite code generated")
	})

	inviteBox := container.NewBorder(nil, nil, nil,
		container.NewHBox(copyBtn, refreshBtn),
		inviteCodeEntry,
	)

	// Stop hosting button
	stopHostingBtn := widget.NewButton("Stop Hosting", func() {
		// Stop control server
		stopControlServer(state, addLog)
		
		// Stop Nebula process
		stopNebula(state, addLog)
		
		state.mode = ""
		state.showClients = false
		if state.clientsWindow != nil {
			state.clientsWindow.Close()
			state.clientsWindow = nil
		}
		setStatus("Hosting stopped")
		updateContent()
	})
	stopHostingBtn.Importance = widget.WarningImportance

	// Clients list toggle button (opens popup window)
	var clientsToggleBtn *widget.Button
	clientsToggleBtn = widget.NewButtonWithIcon("", theme.NavigateNextIcon(), func() {
		if state.clientsWindow == nil {
			// Open clients window
			state.showClients = true
			state.clientsWindow = app.NewWindow("Connected Clients")
			state.clientsWindow.SetFixedSize(true)

			clientsContent := container.NewVBox()
			buildClientsPanel(state, clientsContent, setStatus, addLog)

			state.clientsWindow.SetContent(clientsContent)
			state.clientsWindow.Resize(fyne.NewSize(250, 300))
			
			// Auto-refresh clients list every 2 seconds
			go func() {
				ticker := time.NewTicker(2 * time.Second)
				defer ticker.Stop()
				
				for range ticker.C {
					if state.clientsWindow == nil {
						return // Window closed
					}
					// Refresh client list
					fyne.Do(func() {
						if state.clientsWindow != nil {
							newContent := container.NewVBox()
							buildClientsPanel(state, newContent, setStatus, addLog)
							state.clientsWindow.SetContent(newContent)
						}
					})
				}
			}()

			// Handle window close
			state.clientsWindow.SetOnClosed(func() {
				state.showClients = false
				state.clientsWindow = nil
				clientsToggleBtn.SetIcon(theme.NavigateNextIcon())
				setStatus("Clients window closed")
			})

			clientsToggleBtn.SetIcon(theme.NavigateBackIcon())
			state.clientsWindow.Show()
			setStatus("Clients window opened")
		} else {
			// Close clients window
			state.clientsWindow.Close()
			state.clientsWindow = nil
			state.showClients = false
			clientsToggleBtn.SetIcon(theme.NavigateNextIcon())
			setStatus("Clients window closed")
		}
	})
	clientsToggleBtn.Importance = widget.LowImportance

	return container.NewVBox(
		widget.NewLabel("Invite Code"),
		inviteBox,
		stopHostingBtn,
		container.NewBorder(nil, nil, widget.NewLabel("Connected Clients"), clientsToggleBtn, nil),
	)
}

func buildJoinView(state *AppState, updateContent func(), setStatus func(string), addLog func(string), window fyne.Window) fyne.CanvasObject {
	// Invite code input field
	inviteCodeEntry := widget.NewEntry()
	inviteCodeEntry.SetPlaceHolder("Paste invite code")

	// Paste from clipboard button
	pasteBtn := widget.NewButtonWithIcon("", theme.ContentPasteIcon(), func() {
		clipboardContent := window.Clipboard().Content()
		inviteCodeEntry.SetText(clipboardContent)
		setStatus("Invite code pasted from clipboard")
	})

	// Join network button
	joinBtn := widget.NewButton("Join", func() {
		if inviteCodeEntry.Text == "" {
			setStatus("Please enter invite code")
			return
		}
		
		setStatus("Joining network...")
		
		// Join in background
		go func() {
			// Set config directory for client mode
			if err := setConfigDir("client"); err != nil {
				setStatus("Failed to initialize client directory: " + err.Error())
				return
			}
			
			// Parse invite code
			invite, err := parseInviteCode(inviteCodeEntry.Text)
			if err != nil {
				setStatus("Invalid invite code: " + err.Error())
				return
			}
			
			addLog("Invite code accepted")
			addLog(fmt.Sprintf("Connecting to host at %s", invite.HostIP))
			
			// Generate client certificate
			clientIP, err := generateClientCert(state.deviceName, invite, addLog)
			if err != nil {
				setStatus("Failed to generate certificate: " + err.Error())
				return
			}
			
			state.clientIP = clientIP
			
			// Create client config
			if err := createClientConfig(clientIP, state.deviceName, invite, addLog); err != nil {
				setStatus("Failed to create config: " + err.Error())
				return
			}
			
			// Start Nebula as client
			if err := startNebulaHost(state, addLog); err != nil { // Reusing same start function
				setStatus("Failed to start Nebula: " + err.Error())
				return
			}
			
			setStatus(fmt.Sprintf("Connected! IP: %s", clientIP))
			
			// Wait for Nebula interface and handshake to complete
			addLog("Waiting for Nebula handshake...")
			time.Sleep(5 * time.Second)
			
			// Connect to host control server via Nebula overlay (always 100.200.0.1)
			if err := connectToControlServer(state, "100.200.0.1", addLog, updateContent); err != nil {
				addLog("Warning: Failed to connect to control server: " + err.Error())
			}
			
			// Update UI to enable disconnect button
			fyne.Do(func() {
				updateContent()
			})
		}()
	})
	joinBtn.Importance = widget.HighImportance

	inviteBox := container.NewBorder(nil, nil, nil,
		container.NewHBox(pasteBtn, joinBtn),
		inviteCodeEntry,
	)

	// Back/Disconnect button (changes based on connection state)
	var backDisconnectBtn *widget.Button
	if state.kickedByHost {
		// Kicked: Show "Back" button
		backDisconnectBtn = widget.NewButton("Back to Menu", func() {
			state.mode = ""
			state.kickedByHost = false
			setStatus("Ready")
			updateContent()
		})
		backDisconnectBtn.Importance = widget.DangerImportance
	} else if state.isConnected {
		// Connected: Show status in button
		if state.isApproved {
			// Approved: Show "Disconnect" button
			backDisconnectBtn = widget.NewButton("Disconnect", func() {
				// Disconnect from control server
				disconnectFromControlServer(state)
				
				// Stop Nebula process
				stopNebula(state, addLog)
				
				state.mode = ""
				state.clientIP = ""
				state.isApproved = false
				setStatus("Disconnected")
				updateContent()
			})
			backDisconnectBtn.Importance = widget.WarningImportance
		} else {
			// Pending approval: Show status in button
			backDisconnectBtn = widget.NewButton("Pending Approval...", func() {
				// Can still disconnect while pending
				disconnectFromControlServer(state)
				stopNebula(state, addLog)
				
				state.mode = ""
				state.clientIP = ""
				state.isApproved = false
				setStatus("Disconnected")
				updateContent()
			})
			backDisconnectBtn.Importance = widget.LowImportance
		}
	} else {
		// Not connected: Show "Back" button
		backDisconnectBtn = widget.NewButton("Back", func() {
			state.mode = ""
			setStatus("Ready")
			updateContent()
		})
		backDisconnectBtn.Importance = widget.LowImportance
	}

	// Build layout
	return container.NewVBox(
		widget.NewLabel("Invite Code"),
		inviteBox,
		backDisconnectBtn,
	)
}

func buildDeviceNameWidget(state *AppState, updateContent func(), setStatus func(string), app fyne.App) fyne.CanvasObject {
	if state.editingDevice {
		// Edit mode: show input field with save button
		nameEntry := widget.NewEntry()
		nameEntry.SetText(state.deviceName)
		nameEntry.Validator = func(s string) error {
			if len(s) > 16 {
				return fmt.Errorf("max 16 characters")
			}
			return nil
		}

		saveBtn := widget.NewButtonWithIcon("", theme.ConfirmIcon(), func() {
			if len(nameEntry.Text) > 0 && len(nameEntry.Text) <= 16 {
				state.deviceName = nameEntry.Text
				state.editingDevice = false
				updateContent()
			}
		})
		saveBtn.Importance = widget.HighImportance

		return container.NewBorder(nil, nil, widget.NewLabel("Device:"), saveBtn, nameEntry)
	}

	// Display mode: show device name with edit and settings buttons
	editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
		state.editingDevice = true
		updateContent()
	})
	editBtn.Importance = widget.LowImportance

	// Settings button (cogwheel)
	settingsBtn := widget.NewButtonWithIcon("", theme.SettingsIcon(), func() {
		openSettingsWindow(state, setStatus, app)
	})
	settingsBtn.Importance = widget.LowImportance

	nameLabel := widget.NewLabel(state.deviceName)
	return container.NewBorder(nil, nil, widget.NewLabel("Device:"), 
		container.NewHBox(editBtn, settingsBtn), nameLabel)
}

// Open settings window for service/port management
func openSettingsWindow(state *AppState, setStatus func(string), app fyne.App) {
	if state.settingsWindow != nil {
		state.settingsWindow.RequestFocus()
		return
	}

	state.settingsWindow = app.NewWindow("Settings - Exposed Services")
	state.settingsWindow.SetFixedSize(true)

	// Services list
	servicesContainer := container.NewVBox()
	buildServicesPanel(state, servicesContainer, setStatus)

	// Add service form
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Service name (e.g., Minecraft)")

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("Port (e.g., 25565)")

	protoSelect := widget.NewSelect([]string{"tcp", "udp"}, nil)
	protoSelect.SetSelected("tcp")

	addBtn := widget.NewButton("Add Service", func() {
		if nameEntry.Text == "" || portEntry.Text == "" {
			setStatus("Please fill in all fields")
			return
		}

		// Parse port
		var port int
		if _, err := fmt.Sscanf(portEntry.Text, "%d", &port); err != nil || port < 1 || port > 65535 {
			setStatus("Invalid port number (1-65535)")
			return
		}

		// Add service
		state.services = append(state.services, Service{
			Name:  nameEntry.Text,
			Port:  port,
			Proto: protoSelect.Selected,
		})

		setStatus(fmt.Sprintf("Added service: %s (port %d)", nameEntry.Text, port))

		// Clear form
		nameEntry.SetText("")
		portEntry.SetText("")

		// Refresh services list
		servicesContainer.Objects = servicesContainer.Objects[:0]
		buildServicesPanel(state, servicesContainer, setStatus)
		state.settingsWindow.Content().Refresh()
	})
	addBtn.Importance = widget.HighImportance

	addForm := container.NewVBox(
		widget.NewLabel("Add New Service:"),
		widget.NewForm(
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("Port", portEntry),
			widget.NewFormItem("Protocol", protoSelect),
		),
		addBtn,
	)

	content := container.NewBorder(
		widget.NewLabel("Exposed Services"),
		addForm,
		nil,
		nil,
		servicesContainer,
	)

	state.settingsWindow.SetContent(content)
	state.settingsWindow.Resize(fyne.NewSize(350, 400))

	// Handle window close
	state.settingsWindow.SetOnClosed(func() {
		state.settingsWindow = nil
	})

	state.settingsWindow.Show()
}

// Build services panel (list of exposed services)
func buildServicesPanel(state *AppState, panel *fyne.Container, setStatus func(string)) {
	if len(state.services) == 0 {
		noServicesLabel := widget.NewLabel("No services configured")
		noServicesLabel.TextStyle = fyne.TextStyle{Italic: true}
		panel.Objects = append(panel.Objects, noServicesLabel)
		return
	}

	for i, service := range state.services {
		serviceIdx := i // Capture for closure
		serviceLabel := widget.NewLabel(fmt.Sprintf("%s - %s:%d", service.Name, service.Proto, service.Port))

		deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
			// Remove service
			state.services = append(state.services[:serviceIdx], state.services[serviceIdx+1:]...)
			setStatus(fmt.Sprintf("Removed service: %s", service.Name))

			// Refresh services list
			panel.Objects = panel.Objects[:0]
			buildServicesPanel(state, panel, setStatus)
			if state.settingsWindow != nil {
				state.settingsWindow.Content().Refresh()
			}
		})
		deleteBtn.Importance = widget.DangerImportance

		serviceRow := container.NewBorder(nil, nil, nil, deleteBtn, serviceLabel)
		panel.Objects = append(panel.Objects, serviceRow)
	}
}

func buildClientsPanel(state *AppState, panel *fyne.Container, setStatus func(string), addLog func(string)) {
	title := widget.NewLabel("Clients")
	title.TextStyle = fyne.TextStyle{Bold: true}
	panel.Objects = append(panel.Objects, title)

	// Get real client data from ClientManager
	if state.clientManager == nil {
		noClientsLabel := widget.NewLabel("No clients connected")
		panel.Objects = append(panel.Objects, noClientsLabel)
		return
	}

	clients := state.clientManager.GetClients()
	if len(clients) == 0 {
		noClientsLabel := widget.NewLabel("No clients connected")
		panel.Objects = append(panel.Objects, noClientsLabel)
		return
	}

	// Render real client list
	for _, client := range clients {
		clientIP := client.IP
		clientName := client.Name
		clientLabel := widget.NewLabel(fmt.Sprintf("%s (%s)", client.Name, client.IP))

		if client.Status == "pending" {
			// Pending client: show accept button
			acceptBtn := widget.NewButtonWithIcon("", theme.ConfirmIcon(), func() {
				if state.clientManager.ApproveClient(clientIP) {
					setStatus(fmt.Sprintf("Approved %s", clientName))
					
					// Restart Nebula to apply firewall rules (in background)
					go func() {
						if err := restartNebula(state, addLog); err != nil {
							addLog(fmt.Sprintf("Failed to apply firewall rules: %s", err.Error()))
						} else {
							addLog(fmt.Sprintf("Firewall rules updated for %s", clientName))
						}
					}()
				}
			})
			acceptBtn.Importance = widget.SuccessImportance

			clientRow := container.NewBorder(nil, nil, nil, acceptBtn, clientLabel)
			panel.Objects = append(panel.Objects, clientRow)
		} else {
			// Approved client: show kick button
			kickBtn := widget.NewButtonWithIcon("", theme.CancelIcon(), func() {
				state.clientManager.KickClient(clientIP)
				setStatus(fmt.Sprintf("Kicked %s", clientName))
				
				// Restart Nebula to remove firewall rules (in background)
				go func() {
					if err := restartNebula(state, addLog); err != nil {
						addLog(fmt.Sprintf("Failed to update firewall rules: %s", err.Error()))
					} else {
						addLog("Firewall rules updated")
					}
				}()
			})
			kickBtn.Importance = widget.DangerImportance

			clientRow := container.NewBorder(nil, nil, nil, kickBtn, clientLabel)
			panel.Objects = append(panel.Objects, clientRow)
		}
	}
}
