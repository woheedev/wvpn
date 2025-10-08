package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"math/rand"
	"net"
	"net/http"
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

//go:embed binaries/wintun.dll
var wintunDLL []byte

//go:embed binaries/nebula.exe
var nebulaBinary []byte

//go:embed binaries/nebula-cert.exe
var nebulaCertBinary []byte

//go:embed icon.ico
var iconBytes []byte

var (
	tempDir        string
	wintunPath     string
	nebulaPath     string
	nebulaCertPath string
	configDir      string
	baseDir        string
)

type Service struct {
	Name  string `json:"name"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

type RunningApp struct {
	ExeName  string
	TCPPorts []int
	UDPPorts []int
	Selected bool
}

type Settings struct {
	DeviceName  string    `json:"device_name,omitempty"`
	Services    []Service `json:"services,omitempty"`
	RelayServer string    `json:"relay_server,omitempty"`
	RelayPort   int       `json:"relay_port,omitempty"`
	RelayAPIKey string    `json:"relay_api_key,omitempty"`
}

type Client struct {
	Name     string
	IP       string
	Status   string
	ConnTime time.Time
	Conn     net.Conn
}

type ControlMessage struct {
	Type string `json:"type"` // "register", "approve", "kick"
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
}

type ClientManager struct {
	clients map[string]*Client
	mu      sync.RWMutex
	addLog  func(string)
}

// ============================================================================
// SETTINGS PERSISTENCE
// ============================================================================

func loadStartupConfig() (*Settings, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, "wvpn.json")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read startup config: %w", err)
	}

	var config Settings
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse startup config: %w", err)
	}

	if err := os.Remove(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to delete startup config file: %v\n", err)
	}

	return &config, nil
}

func loadSettings() (*Settings, error) {
	settingsPath := filepath.Join(baseDir, "settings.json")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Settings{
				RelayPort: RelayHTTPPort,
			}, nil
		}
		return nil, fmt.Errorf("failed to read settings: %w", err)
	}

	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("failed to parse settings: %w", err)
	}

	// Set default port if missing
	if settings.RelayPort == 0 {
		settings.RelayPort = RelayHTTPPort
	}

	return &settings, nil
}

func saveSettings(state *AppState) error {
	defaultHostname := getHostname()

	settings := Settings{
		Services:    state.services,
		RelayServer: state.relayServer,
		RelayPort:   state.relayPort,
		RelayAPIKey: state.relayAPIKey,
	}

	if state.deviceName != defaultHostname {
		settings.DeviceName = state.deviceName
	}

	return saveSettingsFromStruct(&settings)
}

func saveSettingsFromStruct(settings *Settings) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	settingsPath := filepath.Join(baseDir, "settings.json")
	if err := os.WriteFile(settingsPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write settings: %w", err)
	}

	return nil
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
	inviteCode     string         // Current invite code (6-char code from relay)
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

	// Relay configuration (mandatory)
	relayServer string // Relay server address (IP or domain)
	relayPort   int    // Relay HTTP API port
	relayAPIKey string // API key for host registration

	// Auto-regeneration
	stopAutoRegen chan bool // Signal to stop auto-regeneration
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

	startupConfig, err := loadStartupConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load startup config: %v\n", err)
	}

	settings, err := loadSettings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load settings: %v\n", err)
		settings = &Settings{
			RelayPort: RelayHTTPPort,
		}
	}

	if startupConfig != nil {
		if startupConfig.RelayServer != "" {
			settings.RelayServer = startupConfig.RelayServer
		}
		if startupConfig.RelayPort > 0 {
			settings.RelayPort = startupConfig.RelayPort
		}
		if startupConfig.RelayAPIKey != "" {
			settings.RelayAPIKey = startupConfig.RelayAPIKey
		}
		if err := saveSettingsFromStruct(settings); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to save merged settings: %v\n", err)
		}
	}

	myApp := app.New()
	myWindow := myApp.NewWindow("Wohee's VPN")

	iconResource := fyne.NewStaticResource("icon.ico", iconBytes)
	myWindow.SetIcon(iconResource)

	// Initialize application state with loaded settings
	deviceName := getHostname()
	if settings.DeviceName != "" {
		deviceName = settings.DeviceName
	}

	state := &AppState{
		mode:           "",
		showLogs:       false,
		showClients:    false,
		editingDevice:  false,
		deviceName:     deviceName,
		inviteCode:     "",
		clientIP:       "",
		isConnected:    false,
		isApproved:     false,
		services:       settings.Services,
		clientManager:  nil,
		controlServer:  nil,
		controlClient:  nil,
		clientsWindow:  nil,
		settingsWindow: nil,
		kickedByHost:   false,

		relayServer: settings.RelayServer,
		relayPort:   settings.RelayPort,
		relayAPIKey: settings.RelayAPIKey,

		stopAutoRegen: nil,
	}

	if state.services == nil {
		state.services = []Service{}
	}

	// UI containers
	modeContent := container.NewVBox()
	logsContainer := container.NewVBox()

	// Status label (italic styling for visual separation)
	statusLabel := widget.NewLabel("Ready")
	statusLabel.TextStyle = fyne.TextStyle{Italic: true}
	statusLabel.Wrapping = fyne.TextTruncate
	statusLabel.Truncation = fyne.TextTruncateEllipsis

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
			height += 73
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

	// Cleanup when window closes
	myWindow.SetOnClosed(func() {
		// Stop auto-regeneration if running
		if state.stopAutoRegen != nil {
			close(state.stopAutoRegen)
			state.stopAutoRegen = nil
		}

		// Unregister from relay server if hosting
		if state.mode == "host" && state.inviteCode != "" {
			unregisterFromRelay(state, state.inviteCode, addLog)
		}

		// Stop control server
		if state.controlServer != nil {
			state.controlServer.Close()
		}

		// Kill Nebula process
		if state.nebulaProc != nil {
			state.nebulaProc.Kill()
		}
	})

	myWindow.ShowAndRun()
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func sanitizeDeviceName(name string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, name)
}

func validateRelayServer(server string) error {
	if server == "" {
		return fmt.Errorf("relay server cannot be empty")
	}

	// Check for basic format (hostname or IP)
	if len(server) > 253 {
		return fmt.Errorf("relay server address too long")
	}

	// Check for dangerous characters that could be used for injection
	if strings.ContainsAny(server, " \t\n\r\"'`$(){}[]|&;<>") {
		return fmt.Errorf("relay server contains invalid characters")
	}

	// Basic hostname/IP validation
	if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
		return fmt.Errorf("relay server should not include protocol (http/https)")
	}

	return nil
}

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

// ============================================================================
// APPLICATION DETECTION
// ============================================================================

// Detect running applications with listening ports
func detectRunningApps() ([]RunningApp, error) {
	// Map PID to ports
	type PortInfo struct {
		Port  int
		Proto string
	}
	pidToPorts := make(map[string][]PortInfo)

	// Detect TCP ports
	cmd := exec.Command("netstat", "-ano", "-p", "TCP")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000,
	}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run netstat TCP: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if !strings.Contains(line, "LISTENING") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Parse local address (e.g., "0.0.0.0:25565" or "[::]:25565")
		localAddr := fields[1]
		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon == -1 {
			continue
		}

		portStr := localAddr[lastColon+1:]
		port, err := fmt.Sscanf(portStr, "%d", new(int))
		if err != nil || port == 0 {
			continue
		}
		var portNum int
		fmt.Sscanf(portStr, "%d", &portNum)

		pid := fields[len(fields)-1]
		pidToPorts[pid] = append(pidToPorts[pid], PortInfo{Port: portNum, Proto: "tcp"})
	}

	// Detect UDP ports
	cmd = exec.Command("netstat", "-ano", "-p", "UDP")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000,
	}
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run netstat UDP: %w", err)
	}

	lines = strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address
		localAddr := fields[1]
		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon == -1 {
			continue
		}

		portStr := localAddr[lastColon+1:]
		var portNum int
		if _, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil || portNum == 0 {
			continue
		}

		pid := fields[len(fields)-1]
		pidToPorts[pid] = append(pidToPorts[pid], PortInfo{Port: portNum, Proto: "udp"})
	}

	// Map PID to exe name
	cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000,
	}
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run tasklist: %w", err)
	}

	pidToExe := make(map[string]string)
	lines = strings.Split(string(output), "\n")
	for _, line := range lines {
		// CSV format: "imagename","PID","sessionname","session#","memusage"
		fields := strings.Split(line, "\",\"")
		if len(fields) < 2 {
			continue
		}

		exeName := strings.Trim(fields[0], "\"")
		pidStr := strings.Trim(fields[1], "\"")
		pidToExe[pidStr] = exeName
	}

	// Group by exe name
	exeToApps := make(map[string]*RunningApp)
	for pid, ports := range pidToPorts {
		exeName, exists := pidToExe[pid]
		if !exists {
			continue
		}

		if _, exists := exeToApps[exeName]; !exists {
			exeToApps[exeName] = &RunningApp{
				ExeName:  exeName,
				TCPPorts: []int{},
				UDPPorts: []int{},
			}
		}

		for _, portInfo := range ports {
			if portInfo.Proto == "tcp" {
				// Check if port already exists
				found := false
				for _, p := range exeToApps[exeName].TCPPorts {
					if p == portInfo.Port {
						found = true
						break
					}
				}
				if !found {
					exeToApps[exeName].TCPPorts = append(exeToApps[exeName].TCPPorts, portInfo.Port)
				}
			} else {
				found := false
				for _, p := range exeToApps[exeName].UDPPorts {
					if p == portInfo.Port {
						found = true
						break
					}
				}
				if !found {
					exeToApps[exeName].UDPPorts = append(exeToApps[exeName].UDPPorts, portInfo.Port)
				}
			}
		}
	}

	// Convert to slice
	apps := []RunningApp{}
	for _, app := range exeToApps {
		if len(app.TCPPorts) > 0 || len(app.UDPPorts) > 0 {
			apps = append(apps, *app)
		}
	}

	return apps, nil
}

// Check if a service already exists (deduplication)
func serviceExists(services []Service, port int, proto string) bool {
	for _, s := range services {
		if s.Port == port && s.Proto == proto {
			return true
		}
	}
	return false
}

// ============================================================================
// RELAY API FUNCTIONS
// ============================================================================

// Register network with relay server (host only)
func registerWithRelay(state *AppState, addLog func(string)) (string, error) {
	if state.relayServer == "" {
		return "", fmt.Errorf("relay server not configured - set in Settings")
	}

	if err := validateRelayServer(state.relayServer); err != nil {
		return "", fmt.Errorf("invalid relay server: %w", err)
	}

	if state.relayAPIKey == "" {
		return "", fmt.Errorf("API key required - set in Settings (host only)")
	}

	addLog("Registering with relay server...")

	// Read CA cert and key
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

	// Prepare request
	req := RegisterRequest{
		APIKey: state.relayAPIKey,
		CACert: base64.StdEncoding.EncodeToString(caCertData),
		CAKey:  base64.StdEncoding.EncodeToString(caKeyData),
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request
	url := fmt.Sprintf("https://%s:%d/api/register", state.relayServer, state.relayPort)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(reqBody)))
	if err != nil {
		return "", fmt.Errorf("failed to connect to relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("relay error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var regResp RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	addLog(fmt.Sprintf("Registered! Invite code: %s", regResp.InviteCode))
	return regResp.InviteCode, nil
}

// Fetch network info from relay (client)
func fetchFromRelay(inviteCode string, relayServer string, relayPort int, addLog func(string)) (*InviteResponse, error) {
	addLog("Fetching network info from relay...")

	if err := validateRelayServer(relayServer); err != nil {
		return nil, fmt.Errorf("invalid relay server: %w", err)
	}

	url := fmt.Sprintf("https://%s:%d/api/invite/%s", relayServer, relayPort, strings.ToUpper(inviteCode))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("relay returned error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var inviteResp InviteResponse
	if err := json.NewDecoder(resp.Body).Decode(&inviteResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	addLog("Network info retrieved from relay")
	return &inviteResp, nil
}

// Unregister from relay (host cleanup)
func unregisterFromRelay(state *AppState, inviteCode string, addLog func(string)) {
	if state.relayServer == "" || inviteCode == "" {
		return
	}

	req := UnregisterRequest{
		APIKey:     state.relayAPIKey,
		InviteCode: inviteCode,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return
	}

	url := fmt.Sprintf("https://%s:%d/api/unregister", state.relayServer, state.relayPort)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	httpReq, err := http.NewRequest(http.MethodDelete, url, strings.NewReader(string(reqBody)))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		addLog("Unregistered from relay server")
	}
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

	// Check if client already exists (reconnecting)
	if existingClient, exists := cm.clients[ip]; exists {
		// Update connection and preserve approval status
		existingClient.Conn = conn
		existingClient.ConnTime = time.Now()
		existingClient.Name = name

		if existingClient.Status == "approved" {
			cm.addLog(fmt.Sprintf("Approved client reconnected: %s (%s)", name, ip))
			// Send approval message immediately
			approveMsg := ControlMessage{Type: "approve"}
			json.NewEncoder(conn).Encode(approveMsg)
		} else {
			cm.addLog(fmt.Sprintf("Pending client reconnected: %s (%s)", name, ip))
		}
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
	cm.addLog(fmt.Sprintf("New client connected: %s (%s)", name, ip))
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

// RemoveClient handles client disconnect (preserves approved clients)
func (cm *ClientManager) RemoveClient(ip string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if client, ok := cm.clients[ip]; ok {
		if client.Conn != nil {
			client.Conn.Close()
			client.Conn = nil
		}

		// Only fully remove pending clients
		// Keep approved clients in list for auto-reconnect
		if client.Status == "pending" {
			delete(cm.clients, ip)
			cm.addLog(fmt.Sprintf("Pending client disconnected and removed: %s (%s)", client.Name, ip))
		} else {
			cm.addLog(fmt.Sprintf("Approved client disconnected (kept for reconnect): %s (%s)", client.Name, ip))
		}
	}
}

// ============================================================================
// BINARY EXTRACTION
// ============================================================================

func extractBinaries() error {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = os.Getenv("APPDATA")
	}
	if localAppData == "" {
		return fmt.Errorf("failed to determine AppData directory")
	}

	baseDir = filepath.Join(localAppData, "WoheesVPN")
	tempDir = baseDir

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("failed to create app directory: %w", err)
	}

	wintunDir := filepath.Join(baseDir, "dist", "windows", "wintun", "bin", "amd64")
	if err := os.MkdirAll(wintunDir, 0755); err != nil {
		return fmt.Errorf("failed to create wintun directory: %w", err)
	}

	wintunPath = filepath.Join(wintunDir, "wintun.dll")
	if _, err := os.Stat(wintunPath); os.IsNotExist(err) {
		if err := os.WriteFile(wintunPath, wintunDLL, 0755); err != nil {
			return fmt.Errorf("failed to extract wintun.dll: %w", err)
		}
	}

	nebulaPath = filepath.Join(baseDir, "nebula.exe")
	if _, err := os.Stat(nebulaPath); os.IsNotExist(err) {
		if err := os.WriteFile(nebulaPath, nebulaBinary, 0755); err != nil {
			return fmt.Errorf("failed to extract nebula.exe: %w", err)
		}
	}

	nebulaCertPath = filepath.Join(baseDir, "nebula-cert.exe")
	if _, err := os.Stat(nebulaCertPath); os.IsNotExist(err) {
		if err := os.WriteFile(nebulaCertPath, nebulaCertBinary, 0755); err != nil {
			return fmt.Errorf("failed to extract nebula-cert.exe: %w", err)
		}
	}

	return nil
}

func setConfigDir(mode string) error {
	if baseDir == "" {
		return fmt.Errorf("base directory not initialized")
	}

	configDir = filepath.Join(baseDir, mode, "config")

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return nil
}

// ============================================================================
// NEBULA CERTIFICATE MANAGEMENT
// ============================================================================

func generateCA(addLog func(string)) error {
	caName := "nebula-mesh-ca"
	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")

	os.Remove(caCertPath)
	os.Remove(caKeyPath)

	addLog("Generating new CA certificate for this session...")

	cmd := exec.Command(nebulaCertPath, "ca",
		"-name", caName,
		"-duration", "24h",
		"-out-crt", caCertPath,
		"-out-key", caKeyPath)
	// Clear environment to prevent injection
	cmd.Env = []string{}
	cmd.Dir = configDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000,
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		addLog(fmt.Sprintf("CA generation failed: %s", string(output)))
		return fmt.Errorf("failed to generate CA: %w\nOutput: %s", err, string(output))
	}

	addLog("CA certificate generated (expires in 24 hours)")
	return nil
}

func generateHostCert(deviceName string, addLog func(string)) error {
	hostCertPath := filepath.Join(configDir, "host.crt")
	hostKeyPath := filepath.Join(configDir, "host.key")

	os.Remove(hostCertPath)
	os.Remove(hostKeyPath)

	addLog(fmt.Sprintf("Generating certificate for %s...", deviceName))

	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")

	cmd := exec.Command(nebulaCertPath, "sign",
		"-name", sanitizeDeviceName(deviceName),
		"-ip", "100.200.0.1/24",
		"-duration", "12h",
		"-ca-crt", caCertPath,
		"-ca-key", caKeyPath,
		"-out-crt", hostCertPath,
		"-out-key", hostKeyPath,
	)
	// Clear environment to prevent injection
	cmd.Env = []string{}
	cmd.Dir = configDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000,
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

// Create Nebula config file for host with service firewall rules
func createHostConfigWithServices(services []Service, clientManager *ClientManager, addLog func(string)) error {
	addLog("Creating Nebula configuration...")

	configPath := filepath.Join(configDir, "config.yml")
	caCertPath := filepath.Join(configDir, "ca.crt")
	hostCertPath := filepath.Join(configDir, "host.crt")
	hostKeyPath := filepath.Join(configDir, "host.key")

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

	config += `

logging:
  level: info
  format: text
`

	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	addLog("Configuration file created")
	return nil
}

func generateClientCert(deviceName string, invite *InviteResponse, addLog func(string)) (string, error) {
	clientCertPath := filepath.Join(configDir, "client.crt")
	clientKeyPath := filepath.Join(configDir, "client.key")

	os.Remove(clientCertPath)
	os.Remove(clientKeyPath)

	clientIPNum := rand.Intn(253) + 2
	clientIP := fmt.Sprintf("100.200.0.%d", clientIPNum)
	clientIPWithMask := fmt.Sprintf("%s/24", clientIP)

	addLog(fmt.Sprintf("Generating client certificate for %s...", deviceName))

	caCertData, err := base64.StdEncoding.DecodeString(invite.CACert)
	if err != nil {
		return "", fmt.Errorf("failed to decode CA cert: %w", err)
	}

	caKeyData, err := base64.StdEncoding.DecodeString(invite.CAKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode CA key: %w", err)
	}

	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")

	if err := os.WriteFile(caCertPath, caCertData, 0600); err != nil {
		return "", fmt.Errorf("failed to write CA cert: %w", err)
	}

	if err := os.WriteFile(caKeyPath, caKeyData, 0600); err != nil {
		return "", fmt.Errorf("failed to write CA key: %w", err)
	}

	addLog(fmt.Sprintf("Assigned IP: %s", clientIP))

	cmd := exec.Command(nebulaCertPath, "sign",
		"-name", sanitizeDeviceName(deviceName),
		"-ip", clientIPWithMask,
		"-duration", "12h",
		"-ca-crt", caCertPath,
		"-ca-key", caKeyPath,
		"-out-crt", clientCertPath,
		"-out-key", clientKeyPath,
	)
	// Clear environment to prevent injection
	cmd.Env = []string{}
	cmd.Dir = configDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000,
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		addLog(fmt.Sprintf("Certificate generation failed: %s", string(output)))
		return "", fmt.Errorf("failed to generate client certificate: %w", err)
	}

	addLog(fmt.Sprintf("Client certificate generated: %s (expires in 12h)", clientIP))
	return clientIPWithMask, nil
}

func createClientConfig(_ string, _ string, invite *InviteResponse, addLog func(string)) error {
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
  "%s": ["%s"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "%s"

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
    # Control server access (always allowed)
    - port: 9999
      proto: tcp
      host: "100.200.0.1"
    
    # Note: Approved clients get dynamic firewall rules via host config updates

  inbound:
    # Only control server access initially
    - port: 9999
      proto: tcp
      host: "100.200.0.1"

logging:
  level: info
  format: text
`, caCertPath, clientCertPath, clientKeyPath, invite.HostIP, invite.RelayIP, invite.HostIP)

	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	addLog("Configuration file created")
	return nil
}

// ============================================================================
// NEBULA PROCESS MANAGEMENT
// ============================================================================

func startNebulaHost(state *AppState, addLog func(string)) error {
	addLog("Starting Nebula...")

	configPath := filepath.Join(configDir, "config.yml")

	cmd := exec.Command(nebulaPath, "-config", configPath)
	cmd.Dir = tempDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000 | 0x00000008,
	}

	cmd.Stdout = &nebulaLogger{addLog: addLog, prefix: "[nebula]"}
	cmd.Stderr = &nebulaLogger{addLog: addLog, prefix: "[nebula]"}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Nebula: %w", err)
	}

	state.nebulaProc = cmd.Process
	state.isConnected = true
	addLog(fmt.Sprintf("Nebula started (PID: %d)", cmd.Process.Pid))
	addLog("Host is now running on 100.200.0.1")

	go func() {
		cmd.Wait()
		addLog("Nebula process exited")
		state.nebulaProc = nil
		state.isConnected = false
	}()

	return nil
}

func stopNebula(state *AppState, addLog func(string)) {
	if state.nebulaProc != nil {
		addLog("Stopping Nebula...")
		state.nebulaProc.Kill()
		state.nebulaProc = nil
		state.isConnected = false
		addLog("Nebula stopped")
	}
}

func restartNebula(state *AppState, addLog func(string)) error {
	addLog("Restarting Nebula to apply new firewall rules...")

	if state.nebulaProc != nil {
		state.nebulaProc.Kill()
		state.nebulaProc = nil
		time.Sleep(1 * time.Second)
	}

	if err := createHostConfigWithServices(state.services, state.clientManager, addLog); err != nil {
		return fmt.Errorf("failed to regenerate config: %w", err)
	}

	if err := startNebulaHost(state, addLog); err != nil {
		return fmt.Errorf("failed to restart Nebula: %w", err)
	}

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
// CONTROL PROTOCOL
// ============================================================================

func startControlServer(state *AppState, addLog func(string)) error {
	addLog("Starting control server on 100.200.0.1:9999...")

	listener, err := net.Listen("tcp", "100.200.0.1:9999")
	if err != nil {
		return fmt.Errorf("failed to start control server: %w", err)
	}

	state.controlServer = listener

	if state.clientManager == nil {
		state.clientManager = NewClientManager(addLog)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go handleControlClient(conn, state, addLog)
		}
	}()

	addLog("Control server started")
	return nil
}

func handleControlClient(conn net.Conn, state *AppState, addLog func(string)) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	var msg ControlMessage

	if err := decoder.Decode(&msg); err != nil {
		return
	}

	if msg.Type == "register" {
		clientIP := msg.IP

		state.clientManager.AddClient(msg.Name, clientIP, conn)

		state.clientManager.mu.RLock()
		client, exists := state.clientManager.clients[clientIP]
		isApproved := exists && client.Status == "approved"
		state.clientManager.mu.RUnlock()

		if isApproved {
			approveMsg := ControlMessage{Type: "approve"}
			json.NewEncoder(conn).Encode(approveMsg)
		}

		// Keep connection alive and handle messages
		for {
			if err := decoder.Decode(&msg); err != nil {
				state.clientManager.RemoveClient(clientIP)
				return
			}

			// Handle different message types (if any are added in the future)
			switch msg.Type {
			default:
				// Unknown message type, ignore
			}
		}
	}
}

func stopControlServer(state *AppState, addLog func(string)) {
	if state.controlServer != nil {
		addLog("Stopping control server...")
		state.controlServer.Close()
		state.controlServer = nil
		state.clientManager = nil
	}
}

func connectToControlServer(state *AppState, hostIP string, addLog func(string), updateContent func()) error {
	addLog(fmt.Sprintf("Connecting to control server at %s:9999...", hostIP))

	if err := attemptControlConnection(state, hostIP, addLog, updateContent); err != nil {
		return err
	}

	go func() {
		for {
			time.Sleep(5 * time.Second)

			if state.mode != "join" || state.kickedByHost || !state.isConnected {
				return
			}

			if state.controlClient == nil {
				addLog("Control server disconnected, attempting to reconnect...")

				for i := 0; i < 3; i++ {
					if err := attemptControlConnection(state, hostIP, addLog, updateContent); err == nil {
						addLog("Reconnected to control server")
						break
					}
					time.Sleep(2 * time.Second)
				}
			}
		}
	}()

	return nil
}

func attemptControlConnection(state *AppState, hostIP string, addLog func(string), updateContent func()) error {
	conn, err := net.DialTimeout("tcp", hostIP+":9999", 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to host control server: %w", err)
	}

	state.controlClient = conn

	msg := ControlMessage{
		Type: "register",
		Name: state.deviceName,
		IP:   strings.Split(state.clientIP, "/")[0],
	}

	if err := json.NewEncoder(conn).Encode(msg); err != nil {
		conn.Close()
		state.controlClient = nil
		return fmt.Errorf("failed to register with host: %w", err)
	}

	if !state.isApproved {
		addLog("Registered with host, awaiting approval...")
	}

	go func() {
		decoder := json.NewDecoder(conn)
		for {
			var msg ControlMessage
			if err := decoder.Decode(&msg); err != nil {
				state.controlClient = nil

				if state.kickedByHost {
					addLog("Connection to host closed")
				}

				return
			}

			switch msg.Type {
			case "approve":
				if !state.isApproved {
					state.isApproved = true
					addLog("Host approved your connection")
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

type nebulaLogger struct {
	addLog func(string)
	prefix string
	buffer string
}

func (nl *nebulaLogger) Write(p []byte) (n int, err error) {
	nl.buffer += string(p)

	for {
		idx := strings.Index(nl.buffer, "\n")
		if idx == -1 {
			break
		}

		line := strings.TrimSpace(nl.buffer[:idx])
		if line != "" {
			if strings.Contains(line, "Handshake timed out") {
				nl.buffer = nl.buffer[idx+1:]
				continue
			}
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
			if err := createHostConfigWithServices(nil, nil, addLog); err != nil {
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

			// Register with relay server and get invite code
			code, err := registerWithRelay(state, addLog)
			if err != nil {
				setStatus("Failed to register with relay: " + err.Error())
				addLog("ERROR: " + err.Error())
				return
			}
			state.inviteCode = code

			setStatus("Hosting active on 100.200.0.1")

			// Update UI to show invite code
			fyne.Do(func() {
				updateContent()
			})

			// Start auto-regeneration (every 10 minutes)
			state.stopAutoRegen = make(chan bool)
			go func() {
				ticker := time.NewTicker(10 * time.Minute)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						if state.mode != "host" || !state.isConnected {
							return
						}

						addLog("Auto-regenerating invite code...")

						// Unregister old code
						if state.inviteCode != "" {
							unregisterFromRelay(state, state.inviteCode, addLog)
						}

						// Register new code
						newCode, err := registerWithRelay(state, addLog)
						if err != nil {
							addLog("Auto-regen failed: " + err.Error())
							continue
						}

						state.inviteCode = newCode
						addLog("Invite code auto-regenerated")

						// Update UI
						fyne.Do(func() {
							updateContent()
						})
					case <-state.stopAutoRegen:
						return
					}
				}
			}()
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
	// Invite code display as label for better visibility
	inviteCodeLabel := widget.NewLabel(state.inviteCode)
	inviteCodeLabel.TextStyle = fyne.TextStyle{Monospace: true}

	// Copy invite code to clipboard
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		window.Clipboard().SetContent(state.inviteCode)
		setStatus("Invite code copied to clipboard")
	})

	// Regenerate invite code (re-register with relay)
	refreshBtn := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() {
		go func() {
			// Unregister old code
			if state.inviteCode != "" {
				unregisterFromRelay(state, state.inviteCode, addLog)
			}

			// Register new code
			code, err := registerWithRelay(state, addLog)
			if err != nil {
				setStatus("Failed to register with relay: " + err.Error())
				return
			}

			fyne.Do(func() {
				state.inviteCode = code
				inviteCodeLabel.SetText(state.inviteCode)
				setStatus("New invite code generated")
			})
		}()
	})

	inviteBox := container.NewBorder(nil, nil, nil,
		container.NewHBox(copyBtn, refreshBtn),
		inviteCodeLabel,
	)

	// Stop hosting button
	stopHostingBtn := widget.NewButton("Stop Hosting", func() {
		// Stop auto-regeneration
		if state.stopAutoRegen != nil {
			close(state.stopAutoRegen)
			state.stopAutoRegen = nil
		}

		// Unregister from relay
		if state.inviteCode != "" {
			go unregisterFromRelay(state, state.inviteCode, addLog)
			state.inviteCode = ""
		}

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
			})

			clientsToggleBtn.SetIcon(theme.NavigateBackIcon())
			state.clientsWindow.Show()
		} else {
			// Close clients window
			state.clientsWindow.Close()
			state.clientsWindow = nil
			state.showClients = false
			clientsToggleBtn.SetIcon(theme.NavigateNextIcon())
		}
	})
	clientsToggleBtn.Importance = widget.LowImportance

	// Create clients label with dynamic count and pending indicator
	clientsLabel := widget.NewLabel("Clients")

	// Update clients label with count and pending indicator
	updateClientsLabel := func() {
		clientsLabelText := "Clients"
		if state.clientManager != nil {
			clients := state.clientManager.GetClients()
			// Only count clients with active connections
			connectedCount := 0
			pendingCount := 0
			for _, client := range clients {
				if client.Conn != nil {
					connectedCount++
					if client.Status == "pending" {
						pendingCount++
					}
				}
			}
			if connectedCount > 0 {
				if pendingCount > 0 {
					clientsLabelText = fmt.Sprintf("Clients (%d) !", connectedCount)
				} else {
					clientsLabelText = fmt.Sprintf("Clients (%d)", connectedCount)
				}
			}
		}
		clientsLabel.SetText(clientsLabelText)
	}
	updateClientsLabel()

	// Auto-update clients label every 2 seconds
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if state.mode != "host" || !state.isConnected {
				return
			}
			fyne.Do(func() {
				updateClientsLabel()
			})
		}
	}()

	clientsRow := container.NewBorder(nil, nil, clientsLabel, clientsToggleBtn, nil)

	return container.NewVBox(
		widget.NewLabel("Invite Code"),
		inviteBox,
		stopHostingBtn,
		clientsRow,
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

			// Validate relay server configured
			if state.relayServer == "" {
				setStatus("Relay server not configured - set in Settings")
				return
			}

			// Fetch network info from relay using invite code
			inviteCode := strings.TrimSpace(strings.ToUpper(inviteCodeEntry.Text))
			if len(inviteCode) != InviteCodeLength {
				setStatus(fmt.Sprintf("Invalid invite code (must be %d characters)", InviteCodeLength))
				return
			}

			invite, err := fetchFromRelay(inviteCode, state.relayServer, state.relayPort, addLog)
			if err != nil {
				setStatus("Failed to fetch network info: " + err.Error())
				return
			}

			addLog(fmt.Sprintf("Connecting to host at %s", invite.RelayIP))

			// Generate client certificate with random IP
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
			if err := startNebulaHost(state, addLog); err != nil {
				setStatus("Failed to start Nebula: " + err.Error())
				return
			}

			setStatus(fmt.Sprintf("Connected! IP: %s", clientIP))

			// Wait for Nebula interface and handshake to complete
			addLog("Waiting for Nebula handshake...")
			time.Sleep(5 * time.Second)

			// Connect to host control server via Nebula overlay
			if err := connectToControlServer(state, "100.200.0.1", addLog, updateContent); err != nil {
				addLog("Failed to connect to control server: " + err.Error())
				stopNebula(state, addLog)
				setStatus("Failed to connect to host")
				return
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
				if state.controlClient != nil {
					state.controlClient.Close()
					state.controlClient = nil
				}

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
				if state.controlClient != nil {
					state.controlClient.Close()
					state.controlClient = nil
				}
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
				saveSettings(state)
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

// Open settings window with tabs for services and relay config
func openSettingsWindow(state *AppState, setStatus func(string), app fyne.App) {
	if state.settingsWindow != nil {
		state.settingsWindow.RequestFocus()
		return
	}

	state.settingsWindow = app.NewWindow("Settings")
	state.settingsWindow.SetFixedSize(true)

	// === SERVICES TAB ===
	servicesContainer := container.NewVBox()
	buildServicesPanel(state, servicesContainer, setStatus)

	// Manual entry section
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Service name (e.g., Minecraft)")

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("Port (e.g., 25565)")

	protoSelect := widget.NewSelect([]string{"tcp", "udp"}, nil)
	protoSelect.SetSelected("tcp")

	addManualBtn := widget.NewButton("Add", func() {
		if nameEntry.Text == "" || portEntry.Text == "" {
			setStatus("Please fill in all fields")
			return
		}

		var port int
		if _, err := fmt.Sscanf(portEntry.Text, "%d", &port); err != nil || port < 1 || port > 65535 {
			setStatus("Invalid port number (1-65535)")
			return
		}

		// Check for duplicates
		if serviceExists(state.services, port, protoSelect.Selected) {
			setStatus(fmt.Sprintf("Port %d (%s) already exists", port, protoSelect.Selected))
			return
		}

		state.services = append(state.services, Service{
			Name:  nameEntry.Text,
			Port:  port,
			Proto: protoSelect.Selected,
		})

		saveSettings(state)
		setStatus(fmt.Sprintf("Added service: %s (port %d)", nameEntry.Text, port))

		nameEntry.SetText("")
		portEntry.SetText("")

		servicesContainer.Objects = servicesContainer.Objects[:0]
		buildServicesPanel(state, servicesContainer, setStatus)
		state.settingsWindow.Content().Refresh()
	})
	addManualBtn.Importance = widget.HighImportance

	manualSection := container.NewVBox(
		widget.NewLabel("Manual Entry:"),
		widget.NewForm(
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("Port", portEntry),
			widget.NewFormItem("Protocol", protoSelect),
		),
		addManualBtn,
	)

	// Running applications section with dropdown
	var runningApps []RunningApp
	var selectedAppIndex int = -1

	appOptions := []string{"Scanning..."}
	appSelect := widget.NewSelect(appOptions, func(selected string) {
		// Find selected app index by matching the full display string
		for i, app := range runningApps {
			portInfo := ""
			if len(app.TCPPorts) > 0 {
				portInfo += fmt.Sprintf("TCP: %v", app.TCPPorts)
			}
			if len(app.UDPPorts) > 0 {
				if portInfo != "" {
					portInfo += ", "
				}
				portInfo += fmt.Sprintf("UDP: %v", app.UDPPorts)
			}
			displayText := fmt.Sprintf("%s (%s)", app.ExeName, portInfo)
			if selected == displayText {
				selectedAppIndex = i
				return
			}
		}
		selectedAppIndex = -1
	})
	appSelect.PlaceHolder = "Select application"

	// Track if we should keep scanning
	stopScanning := make(chan bool)

	// Auto-scan every 10 seconds (only while settings window is open)
	go func() {
		// Initial scan
		time.Sleep(500 * time.Millisecond)
		apps, err := detectRunningApps()
		if err != nil {
			apps = []RunningApp{} // Use empty slice if detection fails
		}
		fyne.Do(func() {
			if state.settingsWindow == nil {
				return
			}
			runningApps = apps
			newOptions := []string{}
			for _, app := range apps {
				portInfo := ""
				if len(app.TCPPorts) > 0 {
					portInfo += fmt.Sprintf("TCP: %v", app.TCPPorts)
				}
				if len(app.UDPPorts) > 0 {
					if portInfo != "" {
						portInfo += ", "
					}
					portInfo += fmt.Sprintf("UDP: %v", app.UDPPorts)
				}
				newOptions = append(newOptions, fmt.Sprintf("%s (%s)", app.ExeName, portInfo))
			}
			if len(newOptions) == 0 {
				appSelect.Options = []string{"No applications found"}
			} else {
				appSelect.Options = newOptions
			}
			appSelect.Refresh()
		})

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if state.settingsWindow == nil {
					return
				}

				apps, err := detectRunningApps()
				if err != nil {
					continue
				}

				fyne.Do(func() {
					if state.settingsWindow == nil {
						return
					}
					runningApps = apps
					newOptions := []string{}
					for _, app := range apps {
						portInfo := ""
						if len(app.TCPPorts) > 0 {
							portInfo += fmt.Sprintf("TCP: %v", app.TCPPorts)
						}
						if len(app.UDPPorts) > 0 {
							if portInfo != "" {
								portInfo += ", "
							}
							portInfo += fmt.Sprintf("UDP: %v", app.UDPPorts)
						}
						newOptions = append(newOptions, fmt.Sprintf("%s (%s)", app.ExeName, portInfo))
					}
					if len(newOptions) == 0 {
						appSelect.Options = []string{"No applications found"}
					} else {
						appSelect.Options = newOptions
					}
					appSelect.Refresh()
				})
			case <-stopScanning:
				return
			}
		}
	}()

	addAppBtn := widget.NewButton("Add Application", func() {
		if selectedAppIndex < 0 || selectedAppIndex >= len(runningApps) {
			setStatus("Please select an application")
			return
		}

		app := runningApps[selectedAppIndex]
		added := 0

		// Check for duplicates and add ports
		for _, port := range app.TCPPorts {
			if !serviceExists(state.services, port, "tcp") {
				state.services = append(state.services, Service{
					Name:  strings.TrimSuffix(app.ExeName, ".exe"),
					Port:  port,
					Proto: "tcp",
				})
				added++
			}
		}
		for _, port := range app.UDPPorts {
			if !serviceExists(state.services, port, "udp") {
				state.services = append(state.services, Service{
					Name:  strings.TrimSuffix(app.ExeName, ".exe"),
					Port:  port,
					Proto: "udp",
				})
				added++
			}
		}

		if added > 0 {
			saveSettings(state)
			setStatus(fmt.Sprintf("Added %d ports from %s", added, app.ExeName))

			servicesContainer.Objects = servicesContainer.Objects[:0]
			buildServicesPanel(state, servicesContainer, setStatus)
			state.settingsWindow.Content().Refresh()
		} else {
			setStatus("All ports already exist")
		}

		appSelect.ClearSelected()
		selectedAppIndex = -1
	})
	addAppBtn.Importance = widget.HighImportance

	appsSection := container.NewVBox(
		widget.NewLabel("Running Applications (auto-scans):"),
		appSelect,
		addAppBtn,
	)

	// Make services scrollable to prevent window expansion
	servicesScroll := container.NewVScroll(servicesContainer)
	servicesScroll.SetMinSize(fyne.NewSize(350, 150))

	servicesTab := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Exposed Services"),
			newWhiteSeparator(),
		),
		container.NewVBox(
			newWhiteSeparator(),
			appsSection,
			newWhiteSeparator(),
			manualSection,
		),
		nil,
		nil,
		servicesScroll,
	)

	// === RELAY TAB ===
	relayServerEntry := widget.NewEntry()
	relayServerEntry.SetPlaceHolder("e.g. relay.example.com or 123.45.67.89")
	if state.relayServer != "" {
		relayServerEntry.SetText(state.relayServer)
	}
	relayServerEntry.OnChanged = func(text string) {
		state.relayServer = strings.TrimSpace(text)
		saveSettings(state)
	}

	relayPortEntry := widget.NewEntry()
	relayPortEntry.SetPlaceHolder(fmt.Sprintf("Default: %d", RelayHTTPPort))
	if state.relayPort > 0 && state.relayPort != RelayHTTPPort {
		relayPortEntry.SetText(fmt.Sprintf("%d", state.relayPort))
	}
	relayPortEntry.OnChanged = func(text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			state.relayPort = RelayHTTPPort
			saveSettings(state)
			return
		}
		var port int
		if _, err := fmt.Sscanf(text, "%d", &port); err == nil && port > 0 && port <= 65535 {
			state.relayPort = port
			saveSettings(state)
		}
	}

	relayAPIEntry := widget.NewEntry()
	relayAPIEntry.SetPlaceHolder("Required for hosting")
	if state.relayAPIKey != "" {
		relayAPIEntry.SetText(state.relayAPIKey)
	}
	relayAPIEntry.OnChanged = func(text string) {
		state.relayAPIKey = strings.TrimSpace(text)
		saveSettings(state)
	}

	relayTab := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Server Address", relayServerEntry),
			widget.NewFormItem("HTTPS Port", relayPortEntry),
			widget.NewFormItem("API Key*", relayAPIEntry),
		),
		widget.NewLabel("* Only required for hosting"),
	)

	// Create tabs
	tabs := container.NewAppTabs(
		container.NewTabItem("Services", servicesTab),
		container.NewTabItem("Relay", relayTab),
	)

	state.settingsWindow.SetContent(tabs)
	state.settingsWindow.Resize(fyne.NewSize(400, 450))

	state.settingsWindow.SetOnClosed(func() {
		state.settingsWindow = nil
		close(stopScanning)
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
			saveSettings(state)
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

	// Filter to only show connected clients
	connectedClients := []*Client{}
	for _, client := range clients {
		if client.Conn != nil {
			connectedClients = append(connectedClients, client)
		}
	}

	if len(connectedClients) == 0 {
		noClientsLabel := widget.NewLabel("No clients connected")
		panel.Objects = append(panel.Objects, noClientsLabel)
		return
	}

	// Render connected client list
	for _, client := range connectedClients {
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
