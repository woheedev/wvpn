#!/bin/bash

# Build both wvpn app and relay server for Linux

echo "Building Wohee's VPN..."

# ============================================================================
# BUILD APP (Linux GUI)
# ============================================================================

echo
echo "[1/2] Building Linux GUI application..."

# Check if required source files exist
if [ ! -f "main.go" ]; then
    echo "Error: main.go not found!"
    exit 1
fi

if [ ! -f "shared.go" ]; then
    echo "Error: shared.go not found!"
    exit 1
fi

# Build the Linux application
echo "Building Linux application..."
go build -o wvpn

if [ $? -eq 0 ]; then
    echo "Linux app built successfully: wvpn"
else
    echo "Failed to build Linux app!"
    exit 1
fi

# ============================================================================
# BUILD RELAY (Linux)
# ============================================================================

echo
echo "[2/2] Building Linux relay server..."

# Check if required source files exist
if [ ! -f "relay.go" ]; then
    echo "Error: relay.go not found!"
    exit 1
fi

if [ ! -f "shared.go" ]; then
    echo "Error: shared.go not found!"
    exit 1
fi

# Build the relay server
echo "Building Linux relay server..."
go build -tags relay -o wvpn_relay relay.go shared.go

if [ $? -eq 0 ]; then
    echo "Linux relay built successfully: wvpn_relay"
else
    echo "Failed to build Linux relay!"
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
echo "Output files:"
echo "  wvpn         (Linux GUI application)"
echo "  wvpn_relay   (Linux relay server)"
echo
echo "Done!"
