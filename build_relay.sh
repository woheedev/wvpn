#!/bin/bash

# Build wvpn server for Linux

echo "Building Wohee's VPN..."

# ============================================================================
# BUILD SERVER
# ============================================================================

echo "Building Linux server..."

# Check if required source files exist
if [ ! -f "relay.go" ]; then
    echo "Error: relay.go not found!"
    exit 1
fi

if [ ! -f "shared.go" ]; then
    echo "Error: shared.go not found!"
    exit 1
fi

# Build the server
echo "Building Linux server..."
go build -tags relay -o wvpn_relay relay.go shared.go

if [ $? -eq 0 ]; then
    echo "Linux server built successfully: wvpn_relay"
else
    echo "Failed to build Linux server!"
    exit 1
fi

# ============================================================================
# SUCCESS
# ============================================================================

echo
echo "========================================"
echo "Build completed successfully!"
echo "========================================"
echo
echo "Output file:"
echo "  wvpn_relay   (Linux server)"
echo
echo "Usage:"
echo "  ./wvpn_relay -ip YOUR_PUBLIC_IP -port 4443 -key YOUR_API_KEY"
echo
echo "Done!"
