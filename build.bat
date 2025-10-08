@echo off
REM Build both wvpn app and relay server

echo Building Wohee's VPN...

REM ============================================================================
REM BUILD APP (Windows GUI)
REM ============================================================================

echo.
echo [1/2] Building Windows GUI application...

REM Check if rsrc tool is available
where rsrc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installing rsrc tool...
    go install github.com/akavel/rsrc@latest
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to install rsrc tool!
        pause
        exit /b 1
    )
) else (
    echo rsrc tool already available.
)

REM Check if manifest file exists
if not exist wvpn.manifest (
    echo Error: wvpn.manifest not found!
    pause
    exit /b 1
)

REM Check if icon file exists
if not exist icon.ico (
    echo Warning: icon.ico not found! Building without icon.
    set ICON_FLAG=
) else (
    echo Icon file found: icon.ico
    set ICON_FLAG=-ico icon.ico
)

REM Check if rsrc.syso needs to be regenerated
if not exist rsrc.syso (
    echo Generating Windows resource file with manifest and icon...
    rsrc -manifest wvpn.manifest %ICON_FLAG% -o rsrc.syso
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to generate resource file!
        pause
        exit /b 1
    )
) else (
    echo Resource file already exists, skipping generation.
)

REM Build the Windows application
echo Building Windows application...
go build -ldflags "-H windowsgui" -o wvpn.exe

if %ERRORLEVEL% EQU 0 (
    echo Windows app built successfully: wvpn.exe
) else (
    echo Failed to build Windows app!
    pause
    exit /b 1
)

REM ============================================================================
REM BUILD RELAY (Linux)
REM ============================================================================

echo.
echo [2/2] Building Linux relay server...

REM Check if required source files exist
if not exist relay.go (
    echo Error: relay.go not found!
    pause
    exit /b 1
)

if not exist shared.go (
    echo Error: shared.go not found!
    pause
    exit /b 1
)

REM Set build environment for Linux
set GOOS=linux
set GOARCH=amd64

REM Build the relay server
echo Building Linux relay server...
go build -tags relay -o wvpn_relay relay.go shared.go

if %ERRORLEVEL% EQU 0 (
    echo Linux relay built successfully: wvpn_relay
) else (
    echo Failed to build Linux relay!
    pause
    exit /b 1
)

REM ============================================================================
REM SUCCESS
REM ============================================================================

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Output files:
echo   wvpn.exe      (Windows GUI application)
echo   wvpn_relay    (Linux relay server)
echo.
echo Done!
pause
