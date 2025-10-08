package main

const (
	InviteCodeLength = 6
	InviteCodeChars  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude O/0, I/1
	NetworkSubnet    = "100.200.0.0/24"
	HostIP           = "100.200.0.1"
	RelayUDPPort     = 4242 // Nebula lighthouse port
	RelayHTTPPort    = 4443 // HTTPS API port
)

type RegisterRequest struct {
	APIKey string `json:"api_key"`
	CACert string `json:"ca_cert"` // Base64 encoded
	CAKey  string `json:"ca_key"`  // Base64 encoded
}

type RegisterResponse struct {
	InviteCode string `json:"invite_code"`
	HostIP     string `json:"host_ip"`
	Subnet     string `json:"subnet"`
	RelayIP    string `json:"relay_ip"`
}

type InviteResponse struct {
	CACert  string `json:"ca_cert"`
	CAKey   string `json:"ca_key"`
	RelayIP string `json:"relay_ip"`
	HostIP  string `json:"host_ip"`
	Subnet  string `json:"subnet"`
}

type UnregisterRequest struct {
	APIKey     string `json:"api_key"`
	InviteCode string `json:"invite_code"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
