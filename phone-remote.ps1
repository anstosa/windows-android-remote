# phone-remote.ps1
# Wireless debugging connect helper:
# - Tries mDNS discovery via `adb mdns services`
# - Falls back to manual IP/port entry if mDNS results are missing/ambiguous
# - Starts scrcpy (tries UHID input, then falls back to normal)

param(
  [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

# Detect non-interactive mode: check parameter or if stdin is not available
if (-not $NonInteractive) {
  try {
    $null = [Console]::In
    # If we can't access stdin, we're likely non-interactive
    if (-not $Host.UI.RawUI) {
      $NonInteractive = $true
    }
  }
  catch {
    $NonInteractive = $true
  }
}

# Set script-scoped variable for use in functions
$script:NonInteractive = $NonInteractive

# Track if we originally started in non-interactive mode (before any fallback)
# Check environment variable first (set when falling back to interactive)
if ($env:PHONE_REMOTE_RESTART_NONINTERACTIVE -eq "1") {
  $script:OriginallyNonInteractive = $true
  # Clear the env var so it doesn't persist
  Remove-Item Env:\PHONE_REMOTE_RESTART_NONINTERACTIVE
}
else {
  $script:OriginallyNonInteractive = $NonInteractive
}

# Restart monitoring
$script:RestartRequested = $false

# Load utility modules
$utilsPath = if ($PSScriptRoot) { 
  Join-Path $PSScriptRoot "utils"
} 
else { 
  Join-Path (Split-Path -Parent $MyInvocation.PSCommandPath) "utils"
}

. (Join-Path $utilsPath "Output.ps1")
. (Join-Path $utilsPath "Dependencies.ps1")
. (Join-Path $utilsPath "Input.ps1")
. (Join-Path $utilsPath "Restart.ps1")
. (Join-Path $utilsPath "Network.ps1")
. (Join-Path $utilsPath "Config.ps1")
. (Join-Path $utilsPath "Connection.ps1")
. (Join-Path $utilsPath "Shortcuts.ps1")
. (Join-Path $utilsPath "Firewall.ps1")

# Check and install missing dependencies
Test-AndInstall-Dependencies

if (Test-RestartRequested) { Restart-Script }

# Final verification that dependencies are available
Test-Command adb
Test-Command scrcpy

if (Test-RestartRequested) { Restart-Script }

# Check and optionally create desktop shortcuts
Test-DesktopShortcuts

if (Test-RestartRequested) { Restart-Script }

# Check and create firewall rules
Test-AndCreate-FirewallRules

if (Test-RestartRequested) { Restart-Script }

adb start-server | Out-Null

if (Test-RestartRequested) { Restart-Script }

Show-Banner

# Check if device is already connected before attempting mDNS discovery
$script:bestMatch = $null  # Will hold interface/pairing match if found
$deviceAlreadyConnected = Test-DeviceConnected
if ($deviceAlreadyConnected) {
  Write-Section "Device Already Connected"
  Write-Success "Found an already connected ADB device. Skipping mDNS discovery."
  Write-Host ""
  $useMdns = $false  # Skip mDNS since device is already connected
}
else {
  Write-Section "Discovering Devices"
  Write-Info "Discovering Wireless Debugging services via mDNS..."
  Write-Info "(Press 'r' at any time to restart)" -ForegroundColor DarkGray
  Write-Host ""
  
  # Show network interface information and find best match
  Show-AdbInterfaceInfo
  
  # Try to find interface with saved pairing
  $script:bestMatch = Get-BestInterfaceForPairing
  $preferredSubnet = $null
  if ($script:bestMatch) {
    $preferredSubnet = $script:bestMatch.Subnet
    Write-Info "Auto-selected interface with saved pairing: $($script:bestMatch.Interface.IP) ($($script:bestMatch.Interface.AdapterName)) on subnet $preferredSubnet"
    Write-Host ""
  }
  
  # Show what command we're running
  Write-Info "Running: adb mdns services"
  
  # Try mDNS discovery (no wait times - immediate attempt)
  $script:mdnsDiagnostics = $null
  $all = Get-MdnsServices -diagnostics ([ref]$script:mdnsDiagnostics)

  if (Test-RestartRequested) { Restart-Script }

  # Show detailed diagnostics
  Write-Host ""
  Write-Info "=== mDNS Discovery Results ===" -ForegroundColor Cyan
  if ($script:mdnsDiagnostics) {
    Write-Info "Exit Code: $($script:mdnsDiagnostics.ExitCode)"
    
    if ($script:mdnsDiagnostics.Stderr -and $script:mdnsDiagnostics.Stderr.Count -gt 0) {
      Write-Warning "Stderr output:"
      foreach ($line in $script:mdnsDiagnostics.Stderr) {
        Write-Host "  [STDERR] $line" -ForegroundColor Red
      }
    }
    
    if ($script:mdnsDiagnostics.Stdout -and $script:mdnsDiagnostics.Stdout.Count -gt 0) {
      Write-Info "Raw stdout output ($($script:mdnsDiagnostics.Stdout.Count) lines):"
      foreach ($line in $script:mdnsDiagnostics.Stdout) {
        Write-Host "  [STDOUT] $line" -ForegroundColor Gray
      }
    }
    else {
      Write-Info "No stdout output received"
    }
  }
  else {
    Write-Warning "No diagnostics available"
  }
  
  Write-Host ""
  Write-Info "Processed services count: $($all.Count)"
  if ($all.Count -gt 0) {
    Write-Info "All discovered services:"
    foreach ($svc in $all) {
      Write-Host "  - $svc" -ForegroundColor Gray
    }
  }

  if (Test-RestartRequested) { Restart-Script }

  # Filter to pairing/connect services
  Write-Host ""
  Write-Info "Filtering services for ADB patterns..."
  $pairing = @($all | Where-Object { $_ -match "_adb-tls-pairing" })
  $connect = @($all | Where-Object { $_ -match "_adb-tls-connect" })
  
  Write-Info "Pairing services found: $($pairing.Count)"
  if ($pairing.Count -gt 0) {
    foreach ($svc in $pairing) {
      Write-Host "  [PAIRING] $svc" -ForegroundColor Yellow
    }
  }
  
  Write-Info "Connect services found: $($connect.Count)"
  if ($connect.Count -gt 0) {
    foreach ($svc in $connect) {
      Write-Host "  [CONNECT] $svc" -ForegroundColor Green
    }
  }
  
  Write-Host ""

  $useMdns = $true

  # "Doesn't look good" criteria:
  # - No services at all
  if ($all.Count -eq 0) {
    $useMdns = $false
    
    Write-Warning "=== mDNS Discovery Failed ==="
    Write-Info "No services were discovered."
    
    # Provide diagnostic information
    if ($script:mdnsDiagnostics) {
      if ($script:mdnsDiagnostics.ExitCode -ne 0) {
        Write-Warning "Command failed with exit code: $($script:mdnsDiagnostics.ExitCode)"
        if ($script:mdnsDiagnostics.Stderr -and $script:mdnsDiagnostics.Stderr.Count -gt 0) {
          Write-Info "Error details:"
          foreach ($err in $script:mdnsDiagnostics.Stderr) {
            Write-Host "  $err" -ForegroundColor Red
          }
        }
      }
      elseif ($script:mdnsDiagnostics.Stdout -and $script:mdnsDiagnostics.Stdout.Count -gt 0) {
        Write-Info "Command succeeded but no services matched expected patterns."
        Write-Info "Expected patterns: '_adb-tls-pairing' or '_adb-tls-connect'"
      }
      else {
        Write-Info "Command succeeded but returned no output."
      }
    }
    
    Write-Host ""
    Write-Info "Troubleshooting steps:"
    Write-Host "  1. On your phone: Settings → Developer Options → Wireless Debugging" -ForegroundColor DarkGray
    Write-Host "     - Ensure 'Wireless Debugging' toggle is ON" -ForegroundColor DarkGray
    Write-Host "     - Check that IP address and port are shown" -ForegroundColor DarkGray
    Write-Host "  2. Verify phone and computer are on the same Wi-Fi network" -ForegroundColor DarkGray
    Write-Host "  3. Check Windows Firewall allows mDNS (port 5353/UDP)" -ForegroundColor DarkGray
    Write-Host "  4. Try toggling Wireless Debugging OFF and ON again on your phone" -ForegroundColor DarkGray
    
    # Show network diagnostics to help debug
    Show-NetworkDiagnostics
    
    Write-Info "Note: If mDNS continues to fail, you can use manual connection mode below."
  }
  # If we have connect services but no pairing services, device is already paired - try connecting directly
  elseif ($connect.Count -gt 0 -and $pairing.Count -eq 0) {
    # Device is already paired, try connecting directly
    Write-Info "Found connect service(s) but no pairing service(s) - device appears to be already paired."
    
    if (Test-RestartRequested) { Restart-Script }
    
    $connService = Select-Service $connect "Connect (_adb-tls-connect)"
    if ($connService) {
      if (Test-RestartRequested) { Restart-Script }
      
      Write-Section "Connecting Device"
      # Extract and print IP from connect service
      $connIp = if ($connService -match '^(.+?):') { $matches[1] } else { "N/A" }
      Write-Success "Connecting to device IP: $connIp"
      Write-Info "Attempting to connect to: $connService"
      $connectResult = Test-AdbConnect $connService
      if ($connectResult) {
        Write-Success "Connected successfully via mDNS!"
        $useMdns = $true  # Mark as successful so we don't fall back
      }
      else {
        Write-Warning "=== mDNS Connection Failed ==="
        Write-Warning "Failed to connect via mDNS connect service: $connService"
        Write-Info "The connect service was discovered but connection attempt failed."
        Write-Info "Possible reasons:"
        Write-Host "  - Port may have changed on the device" -ForegroundColor DarkGray
        Write-Host "  - Firewall is blocking the connection" -ForegroundColor DarkGray
        Write-Host "  - Device may need to be re-paired" -ForegroundColor DarkGray
        $useMdns = $false
      }
    }
    else {
      Write-Warning "=== mDNS Discovery Cancelled ==="
      Write-Info "User cancelled connect service selection."
      $useMdns = $false
    }
  }
  # If we have pairing services but no connect services, something is wrong
  elseif ($pairing.Count -gt 0 -and $connect.Count -eq 0) {
    Write-Warning "=== mDNS Discovery Issue ==="
    Write-Warning "Found pairing service(s) but no connect service(s). This is unusual."
    Write-Info "This typically means:"
    Write-Host "  - Device may need to be reset or Wireless Debugging toggled off/on" -ForegroundColor DarkGray
    Write-Host "  - Device may be in an inconsistent state" -ForegroundColor DarkGray
    Write-Host "  - Connect service may appear after pairing completes" -ForegroundColor DarkGray
    $useMdns = $false
  }
  # If we have both, proceed with normal pairing flow
  elseif ($pairing.Count -gt 0 -and $connect.Count -gt 0) {
    Write-Info "Both pairing and connect services found - proceeding with pairing flow."
    # Let user choose if multiple; blank selection triggers manual fallback
    $pairService = Select-Service $pairing "Pairing (_adb-tls-pairing)"
    if (-not $pairService) {
      Write-Warning "=== mDNS Discovery Cancelled ==="
      Write-Info "User cancelled service selection or no service was selected."
      $useMdns = $false 
    }
    else {
      # Skip pairing in non-interactive mode (requires user input)
      if ($script:NonInteractive) {
        Write-Warning "Pairing required but skipped in non-interactive mode."
        $useMdns = $false
      }
      else {
        if (Test-RestartRequested) { Restart-Script }
        
        Write-Section "Pairing Device"
        # Extract and print IP from pairing service
        $pairIp = if ($pairService -match '^(.+?):') { $matches[1] } else { "N/A" }
        Write-Success "Pairing with device IP: $pairIp"
        Write-Host ""
        Write-Info "On phone: Developer options -> Wireless debugging -> Pair device with pairing code"
        $code = Read-HostWithRestart "Enter pairing code from phone"
        
        if (Test-RestartRequested) { Restart-Script }
        
        Write-Info "Pairing with device..."
        adb pair $pairService $code

        if (Test-RestartRequested) { Restart-Script }

        Write-Section "Connecting Device"
        Write-Info "Refreshing mDNS services after pairing..."
        
        # Refresh connect list after pairing
        $mdnsDiagnostics2 = $null
        $all2 = Get-MdnsServices -diagnostics ([ref]$mdnsDiagnostics2)
        
        Write-Info "Second mDNS discovery results:"
        Write-Info "  Services found: $($all2.Count)"
        if ($mdnsDiagnostics2) {
          Write-Info "  Exit code: $($mdnsDiagnostics2.ExitCode)"
          if ($mdnsDiagnostics2.Stderr -and $mdnsDiagnostics2.Stderr.Count -gt 0) {
            Write-Warning "  Stderr: $($mdnsDiagnostics2.Stderr -join '; ')"
          }
        }
        if ($all2.Count -gt 0) {
          Write-Info "  All services:"
          foreach ($svc in $all2) {
            Write-Host "    - $svc" -ForegroundColor Gray
          }
        }
        
        if (Test-RestartRequested) { Restart-Script }
        
        $connect2 = @($all2 | Where-Object { $_ -match "_adb-tls-connect" })
        Write-Info "  Connect services found: $($connect2.Count)"
        if ($connect2.Count -eq 0) {
          Write-Warning "=== mDNS Discovery Failed After Pairing ==="
          Write-Warning "No connect services found after pairing completed."
          Write-Info "This may indicate:"
          Write-Host "  - Pairing succeeded but connect service hasn't appeared yet" -ForegroundColor DarkGray
          Write-Host "  - Device needs a moment to register the connect service" -ForegroundColor DarkGray
          Write-Host "  - Try manual connection mode with the IP and port from Wireless Debugging screen" -ForegroundColor DarkGray
          $useMdns = $false
        }
        else {
          $connService = Select-Service $connect2 "Connect (_adb-tls-connect)"
          if (-not $connService) {
            Write-Warning "=== mDNS Discovery Cancelled ==="
            Write-Info "User cancelled connect service selection."
            $useMdns = $false
          }
          else {
            if (Test-RestartRequested) { Restart-Script }
            
            # Extract and print IP from connect service
            $connIp = if ($connService -match '^(.+?):') { $matches[1] } else { "N/A" }
            Write-Info "Attempting to connect to: $connService (IP: $connIp)"
            $connectResult = Test-AdbConnect $connService
            if ($connectResult) {
              Write-Success "Connected successfully via mDNS!"
            }
            else {
              Write-Warning "Connection attempt failed for: $connService"
              Write-Info "This may indicate the port changed or there's a connectivity issue."
            }
          }
        }
      }
    }
  }
  else {
    # No services found
    $useMdns = $false
  }
}

# Only show mDNS warning and try fallback if device is not already connected
if (-not $useMdns -and -not $deviceAlreadyConnected) {
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Warning "mDNS discovery didn't look usable."
  # Additional diagnostics may have been shown above
  Write-Host ""
  
  # Try remembered pairings first - use preferred subnet from interface matching if available
  $targetSubnet = $null
  if ($script:bestMatch) {
    $targetSubnet = $script:bestMatch.Subnet
    Write-Info "Attempting connection using interface with saved pairing (subnet: $targetSubnet)..."
  }
  else {
    # Detect subnet first so we can use it for default IP if remembered pairings fail
    $targetSubnet = Get-CurrentSubnet
    if ($targetSubnet) {
      Write-Info "Detected current subnet: $targetSubnet"
    }
  }
  
  if (Connect-RememberedPairings -filterSubnet $targetSubnet) {
    if (Test-RestartRequested) { Restart-Script }
    Write-Success "Successfully connected using remembered pairing."
  }
  else {
    if (Test-RestartRequested) { Restart-Script }
    Write-Warning "No remembered pairings worked. Falling back to manual mode."
    # Use IP from the best match interface's pairing if available, otherwise fall back to config default
    $defaultIp = $null
    if ($script:bestMatch) {
      $pairingIp = Get-PairingProperty $script:bestMatch.Pairing "ip"
      if ($pairingIp) {
        $defaultIp = $pairingIp
        Write-Info "Using saved pairing IP as default: $defaultIp"
      }
    }
    elseif ($targetSubnet) {
      $cfg = Import-Config
      if ($cfg.pairings -and $cfg.pairings[$targetSubnet]) {
        $subnetPairing = $cfg.pairings[$targetSubnet]
        $ip = Get-PairingProperty $subnetPairing "ip"
        if ($ip) {
          $defaultIp = $ip
        }
      }
    }
    if (-not $defaultIp) {
      $defaultIp = Get-DefaultIpFromConfig
    }
    $ok = ConnectOrPairManual $defaultIp
    if (-not $ok) {
      if (Test-RestartRequested) { Restart-Script }
      Write-Host ""
      if ($script:NonInteractive) {
        Write-Warning "Could not connect/pair in non-interactive mode."
        Write-Info "Re-launching in interactive mode to allow manual connection..."
        Start-InteractiveMode
      }
      else {
        Write-Error "Could not connect/pair. Check Wireless debugging screen and try again."
        throw "Could not connect/pair. Check Wireless debugging screen and try again."
      }
    }
  }
}

if (Test-RestartRequested) { Restart-Script }

# Check if a device is connected
$deviceConnected = Test-DeviceConnected
if (-not $deviceConnected) {
  if ($script:NonInteractive) {
    Write-Warning "No connection established in non-interactive mode."
    Write-Info "Re-launching in interactive mode to allow manual connection..."
    Start-InteractiveMode
  }
  else {
    throw "No connected ADB device after pairing/connect. Check Wireless debugging status and try again."
  }
}

# Pick first connected device (should now be present)
$serial = (adb devices | Select-String "device$" | Select-Object -First 1 | ForEach-Object { ($_ -split "\s+")[0] })
if ([string]::IsNullOrWhiteSpace($serial)) {
  if ($script:NonInteractive) {
    Write-Warning "No connected ADB device found."
    Write-Info "Re-launching in interactive mode to allow manual connection..."
    Start-InteractiveMode
  }
  else {
    throw "No connected ADB device after pairing/connect. Check Wireless debugging status and try again."
  }
}

# Best-effort IP display
$ip = ""
try {
  $ip = adb -s $serial shell "ip -4 route 2>/dev/null | grep -oE 'src [0-9.]+' | head -n 1 | awk '{print \$2}'" 2>$null
}
catch {}
$ip = $ip.Trim()
if ([string]::IsNullOrWhiteSpace($ip)) { $ip = "N/A" }

Write-Host ""
Write-Section "Connection Successful"
Write-Success "Connected device: $serial"
Write-Success "Device IP: $ip"
Write-Host ""

# If we originally started non-interactive and fell back to interactive, restart in non-interactive mode
if ($script:OriginallyNonInteractive -and -not $script:NonInteractive) {
  Write-Info "Connection established. Restarting in non-interactive mode..."
  Start-Sleep -Seconds 1
  
  $scriptPath = if ($PSScriptRoot) { 
    Join-Path $PSScriptRoot "phone-remote.ps1"
  } 
  else { 
    $MyInvocation.PSCommandPath
  }
  
  $powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
  $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -NonInteractive"
  
  Start-Process -FilePath $powershellExe -ArgumentList $arguments
  exit 0
}

Write-Section "Starting Remote Session"
Write-Info "Starting scrcpy..."
Write-Host ""

# Use UHID keyboard (works great) but SDK mouse (lower latency than UHID mouse)
try {
  & scrcpy --serial $serial --keyboard=uhid --mouse=sdk
}
catch {
  Write-Warning "UHID keyboard failed; falling back to regular scrcpy control..."
  & scrcpy --serial $serial --no-playback
}

