@echo off

echo ======================================
echo FireBounty v2 Installer
echo ======================================

where go >nul 2>nul

if %errorlevel% neq 0 (
    echo.
    echo [!] Go is not installed
    echo Download:
    echo https://go.dev/dl/
    echo.
    pause
    exit /b
)

pip install -r requirements.txt

echo.
echo Installing FireBounty tools...
echo.

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

go install github.com/tomnomnom/assetfinder@latest

go install github.com/projectdiscovery/httpx/cmd/httpx@latest

go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

go install github.com/projectdiscovery/katana/cmd/katana@latest

go install github.com/lc/gau/v2/cmd/gau@latest

go install github.com/tomnomnom/waybackurls@latest

mkdir outputs
mkdir outputs\recon
mkdir outputs\endpoints
mkdir outputs\findings
mkdir outputs\reports

echo.
echo ======================================
echo FireBounty Installation Complete
echo ======================================

pause