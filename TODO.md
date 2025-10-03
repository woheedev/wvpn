# Nebula VPN Mesh Network Tool - Development Roadmap

## Phase 1: Project Setup ✓ COMPLETE

- [x] Create project structure
- [x] Initialize go.mod with Fyne v2.6.3 (latest)
- [x] Create basic Fyne GUI with all UI elements
- [x] Create binaries folder structure (nebula.exe, nebula-cert.exe, wintun.dll)
- [x] Verify project builds successfully
- [x] Redesign GUI to be compact (300px width, dynamic height)
- [x] Implement mode selection (HOST/JOIN) with context-aware UI
- [x] Add device name editing with 16-char limit and validation
- [x] Add collapsible logs (bottom-right dropdown toggle)
- [x] Add icon buttons (copy, refresh, paste, edit, kick, accept)
- [x] Implement clients list as separate popup window
- [x] Make driver install/uninstall conditional based on status
- [x] Disable window resize and maximize for consistent UI
- [x] Add italic styling to status label for visual separation
- [x] Fix UI overlap bug on startup
- [x] Optimize UI rendering (only middle content updates on mode change)
- [x] Use switch statement instead of if-else chain
- [x] Change separators to white for better visibility
- [x] Remove deprecated dark theme (respects system theme)
- [x] Clean up code structure and remove unnecessary variables
- [x] Final build with `-ldflags "-H windowsgui"` for production
- [x] All dummy data in place and ready for real implementation

## Phase 2: Binary Extraction & Management ✓ COMPLETE

**Goal: Embed and extract binaries at runtime**

### Tasks:

- [x] Add `embed` package import to main.go
- [x] Embed nebula.exe, nebula-cert.exe, wintun.dll using `//go:embed`
- [x] Create function to extract embedded binaries to fixed directory on startup
- [x] Use %LOCALAPPDATA%\NebulaVPN\ (avoids Windows Firewall prompts)
- [x] Add error handling for extraction failures
- [x] Store paths to extracted binaries in global variables for later use
- [x] Persist directory between runs (certificates, config, binaries)

**Acceptance Criteria:**

- ✓ Binaries extracted to %LOCALAPPDATA%\NebulaVPN\ on app start
- ✓ Fixed path avoids repeated Windows Firewall prompts
- ✓ Certificates and config persist between runs

## Phase 3: Certificate Generation ✓ COMPLETE

**Goal: Generate CA certificate and client certificates using nebula-cert**

### Tasks:

- [x] Create function to generate CA certificate (host only)
- [x] Create function to generate host certificate (100.200.0.1/24)
- [x] Create function to generate client certificates (random 100.200.0.2-254)
- [x] Skip generation if certificates already exist (persist between runs)
- [x] Execute nebula-cert.exe with proper arguments (hidden console window)
- [x] Add error handling for certificate generation failures
- [x] Store certificate paths in configDir

**Acceptance Criteria:**

- ✓ CA certificate generates for host with reuse logic
- ✓ Client certificates generate with random IPs (2-254 range)
- ✓ Certificate files stored in %LOCALAPPDATA%\NebulaVPN\config\
- ✓ Certificates persist between application restarts

## Phase 4: Config File Generation ✓ COMPLETE

**Goal: Generate nebula config.yml for host and clients**

### Tasks:

- [x] Create config file template structure
- [x] Implement function to generate host config with dynamic firewall rules
- [x] Configure lighthouse settings (host is lighthouse on port 4242)
- [x] Set PKI paths (ca.crt, host.crt/client.crt, keys)
- [x] Configure firewall rules (service-based with client approval)
- [x] Set tun device names (nebula-host, nebula-client)
- [x] Implement function to generate client config
- [x] Use localhost (127.0.0.1:4242) for local testing
- [x] Write configs to %LOCALAPPDATA%\NebulaVPN\config\
- [x] Dynamic firewall updates when approving clients

**Acceptance Criteria:**

- ✓ Host config generates with dynamic service rules
- ✓ Client config generates with lighthouse pointing to host
- ✓ Firewall rules restrict unapproved clients to control server only
- ✓ Approved clients get access to configured services

## Phase 5: Nebula Process Management ✓ COMPLETE

**Goal: Launch and manage nebula.exe process**

### Tasks:

- [x] Create function to start nebula.exe with config file
- [x] Use os/exec with -config flag
- [x] Hide console windows (CREATE_NO_WINDOW | DETACHED_PROCESS)
- [x] Capture stdout/stderr to logs display with timestamps
- [x] Store process reference in AppState
- [x] Create function to stop nebula.exe process (graceful kill)
- [x] Add process monitoring (detect crashes, log exit)
- [x] Redirect nebula output to GUI logs display
- [x] Implement restart function for firewall rule updates
- [x] Track connection state (isConnected flag)

**Acceptance Criteria:**

- ✓ Nebula starts with config, no visible console windows
- ✓ Process stops cleanly on disconnect or app close
- ✓ Logs appear in GUI with [nebula] prefix
- ✓ Status updates reflect process state
- ✓ Restart works for dynamic firewall updates

## Phase 6: Host Network Implementation ✓ COMPLETE

**Goal: Implement "Host Network" functionality**

### Tasks:

- [x] Wire up HOST button with full workflow
- [x] Validate device name (max 16 chars)
- [x] Generate CA certificate (skip if exists)
- [x] Generate host certificate (100.200.0.1/24)
- [x] Generate host config file with firewall rules
- [x] Start nebula process in background
- [x] Start control server (TCP port 9999)
- [x] Generate invite code (base64 JSON)
- [x] Display invite code in GUI with copy/refresh buttons
- [x] Update status label during each step
- [x] Error handling for all steps
- [x] "Stop Hosting" button returns to mode selection

**Acceptance Criteria:**

- ✓ Host starts successfully and displays invite code
- ✓ Status updates show progress in logs
- ✓ Host acts as lighthouse on port 4242
- ✓ Control server tracks client connections

## Phase 7: Join Network Implementation ✓ COMPLETE

**Goal: Implement "Join Network" functionality**

### Tasks:

- [x] Wire up JOIN button with paste functionality
- [x] Parse invite code (base64 JSON with CA cert, CA key, host IP, network)
- [x] Validate invite code format
- [x] Generate client certificate with random IP (2-254)
- [x] Generate client config with lighthouse settings
- [x] Start nebula process as client
- [x] Connect to host control server (100.200.0.1:9999)
- [x] Send registration message with device name and IP
- [x] Dynamic button ("Back" when not connected, "Disconnect" when connected)
- [x] Show approval status ("⏳ Awaiting host approval" / "✅ Approved")
- [x] Handle kick by host (show "Back to Menu" button)
- [x] Auto-reconnect to control server if connection lost

**Acceptance Criteria:**

- ✓ Client parses and validates invite codes
- ✓ Client joins network and connects via Nebula overlay
- ✓ Control protocol registers client with host
- ✓ UI updates based on approval status
- ✓ Auto-reconnect handles brief disconnections

## Phase 8: Client List & Kick Functionality ✓ COMPLETE

**Goal: Show connected clients and allow host to kick them**

### Tasks:

- [x] Implement ClientManager for tracking connections
- [x] Store clients with IP, name, status (pending/approved), connection time
- [x] Update clients list via control protocol (register messages)
- [x] Create popup window for clients list (250x300px)
- [x] Auto-refresh clients list every 2 seconds
- [x] Wire up approve button (✓ icon) for pending clients
- [x] Wire up kick button (X icon) for approved clients
- [x] Implement kick functionality (send kick message, close connection)
- [x] Implement approve functionality (send approve message, update firewall)
- [x] Restart Nebula when approving/kicking to apply firewall changes
- [x] Clients list shows real-time connection status

**Acceptance Criteria:**

- ✓ Connected clients appear in popup with device names
- ✓ Host can approve pending clients (triggers firewall update)
- ✓ Host can kick approved clients (removes access)
- ✓ Client receives kick message and disconnects
- ✓ List updates automatically every 2 seconds

## Phase 9: Invite Code Generation/Parsing ✓ COMPLETE

**Goal: Implement invite code format and certificate distribution**

### Tasks:

- [x] Design invite code format (base64-encoded JSON)
- [x] Include: CA cert, CA key, host IP (127.0.0.1:4242), network range
- [x] Implement generateInviteCode() (reads CA cert/key from disk)
- [x] Implement parseInviteCode() (decodes base64 JSON)
- [x] Wire up copy button (copies to clipboard via Fyne API)
- [x] Wire up regenerate button (calls generateInviteCode again)
- [x] Certificate distribution: Client generates own cert using embedded CA key
- [x] Validate invite code format before joining

**Note:** Current implementation embeds CA private key in invite (INSECURE, for local testing only)

**Acceptance Criteria:**

- ✓ Invite codes generate with all necessary data
- ✓ Copy to clipboard works
- ✓ Client parses invite codes successfully
- ✓ Client generates own certificate from embedded CA key
- ✓ Regenerate button creates new invite code

## Phase 10: Wintun Driver Management ✓ N/A (Simplified)

**Goal: ~~Implement driver management functionality~~ Use embedded wintun.dll**

### Resolution:

- [x] Wintun.dll embedded and extracted to fixed directory
- [x] Nebula loads wintun.dll from app directory structure
- [x] No explicit install/uninstall needed (Nebula handles it)
- [x] Admin privileges required for Nebula to create network interfaces
- [x] Windows manifest forces admin elevation on app startup

**Acceptance Criteria:**

- ✓ Wintun.dll extracted to proper directory structure on startup
- ✓ Nebula loads driver automatically when creating tun interface
- ✓ No separate driver install/uninstall buttons needed
- ✓ Admin elevation handled via manifest (UAC prompt on start)

## Phase 11: Error Handling & Polish ~ PARTIAL

**Goal: Add robust error handling and improve UX**

### Completed:

- [x] Basic error handling for certificate generation
- [x] Basic error handling for Nebula start/stop
- [x] Input validation for device name (16 char limit)
- [x] Input validation for invite code (base64 format check)
- [x] Service port validation (1-65535)
- [x] UI state management (dynamic buttons based on connection state)
- [x] Graceful shutdown (kill Nebula process on app close)
- [x] Status and logs display for all operations
- [x] Thread-safe UI updates via fyne.Do()

### TODO (Future Enhancements):

- [ ] Persist app state across restarts (device name, services)
- [ ] Add confirmation dialogs for destructive actions
- [ ] File-based logging for debugging
- [ ] More comprehensive network error handling
- [ ] Better handling of edge cases (process crashes, etc.)

**Current Status:**

- Core functionality works reliably
- Basic error handling prevents crashes
- Could use more polish for production use

## Phase 12: Build & Deployment ✓ COMPLETE

**Goal: Create single portable executable**

### Tasks:

- [x] Embed all binaries using go:embed (nebula.exe, nebula-cert.exe, wintun.dll)
- [x] Use `-ldflags "-H windowsgui"` to hide console windows
- [x] Create build_admin.bat script for automated builds
- [x] Embed Windows manifest for admin elevation (rsrc tool)
- [x] Extract binaries to fixed directory (%LOCALAPPDATA%\NebulaVPN)
- [x] Test single .exe portability (no external dependencies)
- [x] Verify wintun.dll extraction and Nebula loading

### Testing Completed:

- [x] Host-client connection over Nebula overlay
- [x] Client approval system via control protocol
- [x] Kick functionality (host can remove clients)
- [x] Reconnection scenarios (auto-reconnect implemented)
- [x] Dynamic firewall rules (services-based access control)
- [x] Multi-instance testing (host + client on same machine)

**Acceptance Criteria:**

- ✓ Single invite_vpn.exe contains everything
- ✓ Runs without installation (portable)
- ✓ Fixed directory avoids Windows Firewall prompts
- ✓ Admin elevation via manifest (UAC on startup)

## Phase 13: Documentation ~ MINIMAL

**Goal: Create user documentation**

### Status:

- [x] Keep TODO.md up to date (main tracking document)
- [x] LICENSE file with third-party attributions (Nebula, Wintun, Fyne)
- [x] Inline code comments for complex sections
- [ ] README.md (not created - user already knows how to use program)

**Rationale:**

User explicitly requested minimal documentation. TODO.md serves as the main reference, and the UI is self-explanatory enough for the intended use case.

--------------------------------------------------------------------------------

## Development Notes

### Network Architecture

- IP Range: 100.200.0.0/24
- Host IP: 100.200.0.1
- Client IPs: 100.200.0.2 - 100.200.0.254
- Default Nebula Port: 4242 (UDP)
- Certificate distribution: HTTP server on host

### Data Storage Locations

- Certificate files: %LOCALAPPDATA%\NebulaVPN\certs\
- Config files: %LOCALAPPDATA%\NebulaVPN\config\
- State file: %LOCALAPPDATA%\NebulaVPN\state.json
- Logs: %LOCALAPPDATA%\NebulaVPN\logs\
- Temp binaries: %TEMP%\NebulaVPN\

### GUI Design Decisions

- Window size: 500x400 (compact)
- Invite codes: 8 characters (A-Z, 0-9) for easy sharing
- Device names: Max 16 characters
- Icon buttons for common actions (copy, refresh, edit, delete)
- Collapsible sections (logs, client list) for clean UI
- Context-aware display (only show relevant UI for HOST/JOIN mode)

### Security Considerations

- Invite codes should expire after reasonable time
- Join tokens should be single-use
- Consider adding simple password protection for invite codes
- **Wintun driver is the ONLY operation requiring admin privileges**
- Admin elevation requested on-demand when Install/Uninstall Driver is clicked
- Main application runs as regular user (no UAC prompt on startup)
- Nebula itself handles mesh network security

### Testing Strategy

1. Test binary extraction on fresh install
2. Test CA and certificate generation
3. Test host startup and lighthouse functionality
4. Test client join with valid invite code
5. Test multiple clients connecting simultaneously
6. Test kick functionality
7. Test disconnect and reconnect
8. Test driver installation/uninstallation
9. Test application restart with existing state
10. Test on different Windows versions

--------------------------------------------------------------------------------

## Current Status: LOCAL TESTING COMPLETE 🎉

### ✓ Completed Phases:

- Phase 1: Project Setup & GUI ✅
- Phase 2: Binary Extraction & Management ✅
- Phase 3: Certificate Generation (session-based, 12h duration) ✅
- Phase 4: Config File Generation ✅
- Phase 5: Nebula Process Management ✅
- Phase 6: Host Network Implementation ✅
- Phase 7: Join Network Implementation ✅
- Phase 8: Client List & Kick/Approve Functionality ✅
- Phase 9: Invite Code Generation/Parsing ✅
- Phase 10: Wintun Driver (simplified, embedded) ✅
- Phase 12: Build & Deployment ✅

### ~ Partial:

- Phase 11: Error Handling & Polish (core works, production-ready for local use)
- Phase 13: Documentation (minimal, TODO.md only)

### 🚀 Working Features (Local Testing):

**Core Functionality:**

- ✅ Host mesh network with invite code generation
- ✅ Join network with invite code (paste from clipboard)
- ✅ Client approval system (pending → approved, persists across restarts)
- ✅ Dynamic firewall rules (service-based access control, IP-specific)
- ✅ Settings menu for configuring exposed services (port, protocol)
- ✅ Kick clients (removes access, triggers firewall update)
- ✅ Auto-reconnect control protocol (survives host restarts)

**Security & Stability:**

- ✅ Unapproved clients restricted to control server only (port 9999)
- ✅ Approved clients get per-IP firewall rules for configured services
- ✅ Session-based certificates (24h CA, 12h signed certs)
- ✅ Fresh CA on each host start (old invite codes become invalid)
- ✅ Approval state persists through Nebula restarts

**User Experience:**

- ✅ Fixed directory (%LOCALAPPDATA%\NebulaVPN) avoids repeated Windows Firewall prompts
- ✅ Separate host/client config directories (allows testing both on same machine)
- ✅ Real-time client list with auto-refresh (2s interval)
- ✅ Timestamped logs with [HH:MM:SS.mmm] format (latest at top)
- ✅ Clean GUI with dynamic button states (Pending Approval/Disconnect/Back)
- ✅ Respects system theme (dark mode by default on Windows)
- ✅ Admin elevation via Windows manifest (UAC prompt on startup)
- ✅ Hidden console windows for all processes

**Technical:**

- ✅ Binary embedding (nebula.exe, nebula-cert.exe, wintun.dll)
- ✅ Automatic binary extraction to fixed directory on startup
- ✅ Control protocol over Nebula overlay (TCP port 9999)
- ✅ ClientManager with thread-safe operations (sync.RWMutex)
- ✅ Host/client distinction via separate config directories

### 📋 Next Steps (Future Enhancements):

**For Internet Use (Not Yet Implemented):**

- [ ] Relay server for NAT traversal (avoid port forwarding)
- [ ] Secure certificate distribution (remove CA key from invite codes)
- [ ] Certificate expiration/renewal handling
- [ ] Proper certificate revocation on kick

**Polish:**

- [ ] Add README.md for distribution
- [ ] Persist app state (device name, services) across restarts
- [ ] Add confirmation dialogs for destructive actions (kick, disconnect)
- [ ] File-based logging for debugging
- [ ] Better error messages for common issues

**Current State:** ✅ Ready for local LAN gaming sessions (temporary, same-network use) ⚠️ Not ready for internet use (requires relay server + security improvements)
