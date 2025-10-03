@echo off
REM Build script that creates an admin-required GUI executable (no console window)

echo Installing rsrc tool (if not already installed)...
go install github.com/akavel/rsrc@latest

echo Generating Windows resource file with manifest...
rsrc -manifest invite_vpn.manifest -o rsrc.syso

echo Building GUI executable (no console window)...
go build -ldflags "-H windowsgui" -o invite_vpn.exe

echo Done!

