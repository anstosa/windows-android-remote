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

# Restart monitoring
$script:RestartRequested = $false

function Test-Command($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Missing required command: '$name'. Install it and ensure it's in PATH."
  }
}

function Install-Dependency($name, $wingetPackage) {
  if ($script:NonInteractive) {
    throw "Missing required dependency: $name. Please install it manually and ensure it's in PATH."
  }
  
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Host ""
  Write-Warning "Missing dependency: $name"
  
  $response = Read-HostWithRestart "Would you like to install it automatically? (Y/n)"
  
  if (Test-RestartRequested) { Restart-Script }
  
  if ($response -match '^[Nn]') {
    throw "Installation cancelled. Please install $name manually and ensure it's in PATH."
  }
  
  Write-Info "Installing $name using winget..."
  try {
    $installResult = & winget install --id $wingetPackage --accept-package-agreements --accept-source-agreements 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Error "Failed to install $name. Error: $installResult"
      throw "Installation failed. Please install $name manually."
    }
    Write-Success "$name installed successfully!"
    
    # Refresh PATH to make the command available
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    # Verify installation
    Start-Sleep -Seconds 2
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
      Write-Warning "$name was installed but may not be in PATH yet. Please restart your terminal or add it to PATH manually."
      throw "$name installation completed but command not found in PATH. Please restart your terminal."
    }
    Write-Success "$name is now available!"
  }
  catch {
    Write-Error "Error installing $name : $_"
    throw "Failed to install $name. Please install it manually."
  }
}

function Test-AndInstall-Dependencies {
  $dependencies = @(
    @{ Name = "adb"; WingetPackage = "Google.PlatformTools" },
    @{ Name = "scrcpy"; WingetPackage = "Genymobile.scrcpy" }
  )
  
  $missing = @()
  foreach ($dep in $dependencies) {
    if (-not (Get-Command $dep.Name -ErrorAction SilentlyContinue)) {
      $missing += $dep
    }
  }
  
  if ($missing.Count -eq 0) {
    return
  }
  
  # In non-interactive mode, skip dependency installation
  if ($script:NonInteractive) {
    $missingNames = ($missing | ForEach-Object { $_.Name }) -join ", "
    throw "Missing required dependencies: $missingNames. Please install them manually and ensure they're in PATH."
  }
  
  Write-Host ""
  Write-Section "Checking Dependencies"
  Write-Info "Checking for required dependencies..."
  
  # Check if winget is available
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Error "winget is not available. Please install Windows Package Manager (winget) first."
    Write-Info "You can install it from: https://aka.ms/getwinget"
    throw "winget is required for automatic dependency installation."
  }
  
  Write-Info "Found winget. Ready to install missing dependencies."
  
  foreach ($dep in $missing) {
    Install-Dependency -name $dep.Name -wingetPackage $dep.WingetPackage
  }
  
  Write-Host ""
  Write-Success "All dependencies are now installed!"
  Write-Host ""
}

function Show-Banner {
  Clear-Host
  Write-Host ""
  Write-Host "==============================================================" -ForegroundColor Cyan
  Write-Host "                                                              " -ForegroundColor Cyan
  Write-Host "                         PHONE REMOTE                         " -ForegroundColor Cyan
  Write-Host "                                                              " -ForegroundColor Cyan
  Write-Host "==============================================================" -ForegroundColor Cyan
  Write-Host ""
}

function Write-Info($message) {
  Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
  Write-Host $message -ForegroundColor White
}

function Write-Success($message) {
  Write-Host "OK: " -ForegroundColor Green -NoNewline
  Write-Host $message -ForegroundColor Green
}

function Write-Warning($message) {
  Write-Host "WARN: " -ForegroundColor Yellow -NoNewline
  Write-Host $message -ForegroundColor Yellow
}

function Write-Error($message) {
  Write-Host "ERROR: " -ForegroundColor Red -NoNewline
  Write-Host $message -ForegroundColor Red
}

function Write-Section($message) {
  Write-Host ""
  Write-Host "--------------------------------------------------------------" -ForegroundColor DarkGray
  Write-Host "  $message" -ForegroundColor Cyan
  Write-Host "--------------------------------------------------------------" -ForegroundColor DarkGray
  Write-Host ""
}

function Test-RestartRequested {
  if ($script:NonInteractive) { return $false }
  if ($script:RestartRequested) {
    return $true
  }
  
  # Check if key is available and is 'r'
  if ([Console]::KeyAvailable) {
    $key = [Console]::ReadKey($true)
    if ($key.KeyChar -eq 'r' -or $key.KeyChar -eq 'R') {
      $script:RestartRequested = $true
      return $true
    }
    # Put the key back if it wasn't 'r' (we'll handle it in the input functions)
    # Actually, we can't put it back easily, so we'll just consume it
    # The input functions will handle their own key reading
  }
  
  return $false
}

function Restart-Script {
  Write-Host ""
  Write-Info "Restarting script..."
  Start-Sleep -Seconds 1
  
  $scriptPath = if ($PSScriptRoot) { 
    Join-Path $PSScriptRoot "phone-remote.ps1"
  } 
  else { 
    $MyInvocation.PSCommandPath
  }
  
  $powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
  $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
  if ($script:NonInteractive) {
    $arguments += " -NonInteractive"
  }
  
  Start-Process -FilePath $powershellExe -ArgumentList $arguments
  exit 0
}

function Read-WithDefault($prompt, $default) {
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Host "  " -NoNewline
  Write-Host "> " -ForegroundColor Cyan -NoNewline
  Write-Host "$prompt (default: $default)" -NoNewline
  Write-Host " (Press 'r' then Enter to restart)" -ForegroundColor DarkGray
  Write-Host "  " -NoNewline
  Write-Host "> " -ForegroundColor Cyan -NoNewline
  
  # Use a custom input loop that checks for 'r'+Enter to restart
  $userInput = ""
  
  while ($true) {
    if (Test-RestartRequested) { Restart-Script }
    
    # Use blocking ReadKey - it will wait for a key press
    $key = [Console]::ReadKey($true)
    
    # Check for Enter key
    if ($key.Key -eq 'Enter' -or $key.KeyChar -eq [char]13 -or $key.KeyChar -eq [char]10) {
      # If input is just 'r' or 'R', restart; otherwise accept input
      if ($userInput -eq 'r' -or $userInput -eq 'R') {
        Restart-Script
      }
      break
    }
    elseif ($key.Key -eq 'Backspace') {
      if ($userInput.Length -gt 0) {
        $userInput = $userInput.Substring(0, $userInput.Length - 1)
        Write-Host "`b `b" -NoNewline
      }
    }
    # Add all printable characters (including 'r')
    elseif (-not [char]::IsControl($key.KeyChar)) {
      $userInput += $key.KeyChar
      Write-Host $key.KeyChar -NoNewline
    }
  }
  
  Write-Host ""
  if ([string]::IsNullOrWhiteSpace($userInput)) { return $default }
  return $userInput
}

function Get-MdnsServices {
  # Returns array of service strings, may be empty.
  try {
    $raw = adb mdns services 2>$null
    if (-not $raw) { return @() }
    return @($raw | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
  }
  catch {
    return @()
  }
}

function Select-Service($services, $label) {
  # If exactly one service, auto-select it. If multiple, ask user. If none, return $null.
  if (-not $services -or $services.Count -eq 0) { return $null }
  if ($services.Count -eq 1) {
    # Extract and print IP for single service
    $service = $services[0]
    $serviceIp = if ($service -match '^(.+?):') { $matches[1] } else { "N/A" }
    Write-Success "Found single $label service (IP: $serviceIp)"
    return $service
  }

  # In non-interactive mode, skip if multiple services
  if ($script:NonInteractive) {
    Write-Warning "Multiple $label services found. Skipping in non-interactive mode."
    return $null
  }

  if (Test-RestartRequested) { Restart-Script }

  Write-Host ""
  Write-Host "  $label services found:" -ForegroundColor Cyan
  for ($i = 0; $i -lt $services.Count; $i++) {
    # Extract IP from each service for display
    $service = $services[$i]
    $serviceIp = if ($service -match '^(.+?):') { $matches[1] } else { "N/A" }
    Write-Host "    " -NoNewline
    Write-Host "[$i]" -ForegroundColor Yellow -NoNewline
    Write-Host " $service " -NoNewline
    Write-Host "(IP: $serviceIp)" -ForegroundColor DarkGray
  }
  Write-Host ""
  
  $idx = Read-HostWithRestart "Enter index to use (blank to skip to manual)"
  if ([string]::IsNullOrWhiteSpace($idx)) { return $null }
  if ($idx -notmatch '^\d+$') { return $null }

  $n = [int]$idx
  if ($n -lt 0 -or $n -ge $services.Count) { return $null }
  return $services[$n]
}

function Read-HostWithRestart($prompt) {
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Host "  " -NoNewline
  Write-Host "> " -ForegroundColor Cyan -NoNewline
  Write-Host "$prompt" -NoNewline
  Write-Host " (Press 'r' then Enter to restart)" -ForegroundColor DarkGray
  Write-Host "  " -NoNewline
  Write-Host "> " -ForegroundColor Cyan -NoNewline
  
  # Use a custom input loop that checks for 'r'+Enter to restart
  $userInput = ""
  
  while ($true) {
    if (Test-RestartRequested) { Restart-Script }
    
    # Use blocking ReadKey - it will wait for a key press
    $key = [Console]::ReadKey($true)
    
    # Check for Enter key
    if ($key.Key -eq 'Enter' -or $key.KeyChar -eq [char]13 -or $key.KeyChar -eq [char]10) {
      # If input is just 'r' or 'R', restart; otherwise accept input
      if ($userInput -eq 'r' -or $userInput -eq 'R') {
        Restart-Script
      }
      break
    }
    elseif ($key.Key -eq 'Backspace') {
      if ($userInput.Length -gt 0) {
        $userInput = $userInput.Substring(0, $userInput.Length - 1)
        Write-Host "`b `b" -NoNewline
      }
    }
    # Add all printable characters (including 'r')
    elseif (-not [char]::IsControl($key.KeyChar)) {
      $userInput += $key.KeyChar
      Write-Host $key.KeyChar -NoNewline
    }
  }
  
  Write-Host ""
  return $userInput
}

function Connect-ManualPair {
  # Manual pairing requires user interaction, skip in non-interactive mode
  if ($script:NonInteractive) {
    return $false
  }
  
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Host ""
  Write-Section "Manual Pairing Mode"
  Write-Info "Using phone's Wireless debugging screen values."
  $defaultIp = Get-ReasonableDefaultIp
  $ip = Read-WithDefault "Enter phone IP" $defaultIp

  if (Test-RestartRequested) { Restart-Script }

  Write-Host ""
  Write-Info "On phone: Developer options -> Wireless debugging -> Pair device with pairing code"
  $pairPort = Read-HostWithRestart "Enter pairing port (shown on pairing screen)"
  
  if (Test-RestartRequested) { Restart-Script }
  
  $code = Read-HostWithRestart "Enter pairing code"

  if (Test-RestartRequested) { Restart-Script }

  adb pair "$ip`:$pairPort" $code

  if (Test-RestartRequested) { Restart-Script }

  Write-Host ""
  Write-Info "On phone: Developer options -> Wireless debugging (main screen)"
  $connectPort = Read-HostWithRestart "Enter connect port (shown on main Wireless debugging screen)"
  
  if (Test-RestartRequested) { Restart-Script }
  
  adb connect "$ip`:$connectPort"
  return $true
}

function Get-ConfigPath {
  $dir = Join-Path $env:APPDATA "phone-remote"
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  return (Join-Path $dir "config.json")
}

function Get-SubnetFromIp($ip) {
  # Extract subnet from IP (e.g., "192.168.12.185" -> "192.168.12")
  if ([string]::IsNullOrWhiteSpace($ip)) { return $null }
  $parts = $ip -split '\.'
  if ($parts.Count -ge 3) {
    return "$($parts[0]).$($parts[1]).$($parts[2])"
  }
  return $null
}

function Get-CurrentSubnet {
  # Try to detect the current machine's local subnet
  # Prioritizes adapters with internet connectivity (default gateway)
  # Returns subnet string (e.g., "192.168.12") or $null if detection fails
  try {
    # Get network adapters with IPv4 addresses, excluding loopback and link-local
    $allAdapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
    Where-Object { 
      $_.IPAddress -notlike "127.*" -and 
      $_.IPAddress -notlike "169.254.*" -and
      $_.IPAddress -notlike "172.22.*" -and # Common VPN subnet
      $_.IPAddress -notlike "172.16.*" -and # Common VPN subnet
      $_.IPAddress -notlike "10.0.*"         # Common VPN subnet (but might be real, so lower priority)
    }
    
    if (-not $allAdapters) { return $null }
    
    # First, try to find adapters with a default gateway (internet connectivity)
    $adaptersWithGateway = @()
    foreach ($adapter in $allAdapters) {
      $ifIndex = $adapter.InterfaceIndex
      $routes = Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
      if ($routes) {
        $adaptersWithGateway += $adapter
      }
    }
    
    # Prefer adapters with internet connectivity
    if ($adaptersWithGateway.Count -gt 0) {
      # Filter out VPN adapters more aggressively
      $preferredAdapters = $adaptersWithGateway | Where-Object {
        $ifIndex = $_.InterfaceIndex
        $ifAlias = (Get-NetAdapter -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue).InterfaceDescription
        # Exclude common VPN adapter names
        if ($ifAlias) {
          $ifAlias -notmatch "VPN|TAP|Virtual|Hyper-V|VMware|VirtualBox|WSL" -and
          $_.IPAddress -notlike "172.22.*" -and
          $_.IPAddress -notlike "172.16.*"
        }
        else {
          $true
        }
      }
      
      if ($preferredAdapters) {
        $localIp = ($preferredAdapters | Select-Object -First 1).IPAddress
        if ($localIp) {
          return Get-SubnetFromIp $localIp
        }
      }
      
      # Fallback to any adapter with gateway
      $localIp = ($adaptersWithGateway | Select-Object -First 1).IPAddress
      if ($localIp) {
        return Get-SubnetFromIp $localIp
      }
    }
    
    # If no adapter with gateway, use first available (excluding VPN subnets)
    $localIp = ($allAdapters | Where-Object { 
        $_.IPAddress -notlike "172.22.*" -and 
        $_.IPAddress -notlike "172.16.*" 
      } | Select-Object -First 1).IPAddress
    
    if ($localIp) {
      return Get-SubnetFromIp $localIp
    }
  }
  catch {
    # Fallback: try ipconfig
    try {
      $ipconfig = ipconfig | Select-String "IPv4" | Select-Object -First 1
      if ($ipconfig -match '(\d+\.\d+\.\d+\.\d+)') {
        return Get-SubnetFromIp $matches[1]
      }
    }
    catch { }
  }
  return $null
}

function Import-Config {
  $path = Get-ConfigPath
  if (Test-Path $path) {
    try { 
      $cfg = Get-Content $path -Raw | ConvertFrom-Json
      # Ensure pairings structure exists and convert to hashtable for easier manipulation
      if (-not $cfg.pairings) {
        $cfg | Add-Member -MemberType NoteProperty -Name 'pairings' -Value @{}
      }
      else {
        # Convert PSCustomObject pairings to hashtable if needed
        $pairingsHash = @{}
        $cfg.pairings.PSObject.Properties | ForEach-Object {
          $pairingsHash[$_.Name] = $_.Value
        }
        $cfg.pairings = $pairingsHash
      }
      return $cfg
    }
    catch { }
  }
  $cfg = [pscustomobject]@{}
  $cfg | Add-Member -MemberType NoteProperty -Name 'pairings' -Value @{}
  return $cfg
}

function Save-Config($cfg) {
  $path = Get-ConfigPath
  ($cfg | ConvertTo-Json -Depth 5) | Set-Content -Encoding UTF8 $path
}

function Set-ConfigProperty($cfg, $name, $value) {
  if (-not $cfg.PSObject.Properties[$name]) {
    $cfg | Add-Member -MemberType NoteProperty -Name $name -Value $value
  }
  else {
    $cfg.$name = $value
  }
}

function Test-AdbConnect($endpoint) {
  # Returns $true if it looks connected/ok, $false otherwise
  if ([string]::IsNullOrWhiteSpace($endpoint)) { return $false }

  $out = & adb connect $endpoint 2>&1 | ForEach-Object { $_.ToString() }
  $text = ($out -join "`n").Trim()

  # Common success-ish outputs:
  # - "connected to ..."
  # - "already connected to ..."
  if ($text -match "connected to|already connected to") { return $true }

  return $false
}

function Test-DeviceConnected {
  # Returns $true if at least one device is connected, $false otherwise
  try {
    $devices = adb devices 2>&1
    $connected = $devices | Select-String "device$" | Where-Object { $_ -notmatch "List of devices" }
    return ($null -ne $connected -and $connected.Count -gt 0)
  }
  catch {
    return $false
  }
}

function Start-InteractiveMode {
  # Re-launch the script in interactive mode
  $scriptPath = if ($PSScriptRoot) { 
    Join-Path $PSScriptRoot "phone-remote.ps1"
  } 
  else { 
    $MyInvocation.PSCommandPath
  }
  
  $powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
  $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
  
  Write-Info "Re-launching in interactive mode..."
  Start-Process -FilePath $powershellExe -ArgumentList $arguments
  exit 0
}

function Connect-RememberedPairings {
  # Try to connect using remembered pairings
  # Optionally filters by subnet if provided
  param([string]$filterSubnet = $null)
  
  $cfg = Import-Config
  if (-not $cfg.pairings -or $cfg.pairings.Count -eq 0) {
    return $false
  }

  # If no subnet filter provided, try to detect current subnet
  if ([string]::IsNullOrWhiteSpace($filterSubnet)) {
    $filterSubnet = Get-CurrentSubnet
    if ($filterSubnet) {
      Write-Info "Detected current subnet: $filterSubnet"
      Write-Host ""
    }
  }

  Write-Info "Trying remembered pairings..."
  $triedAny = $false
  foreach ($subnetKey in $cfg.pairings.Keys) {
    # Skip pairings on different subnets if we have a filter
    if ($filterSubnet -and $subnetKey -ne $filterSubnet) {
      continue
    }
    
    $pairing = $cfg.pairings[$subnetKey]
    # Handle both hashtable and PSCustomObject (from JSON)
    $endpoint = if ($pairing -is [hashtable]) {
      $pairing['connectEndpoint']
    }
    else {
      $pairing.connectEndpoint
    }
    
    if ($endpoint) {
      $triedAny = $true
      # Extract IP from endpoint (format: "ip:port")
      $ip = if ($endpoint -match '^(.+?):') { $matches[1] } else { "N/A" }
      Write-Host "      " -NoNewline
      Write-Host "Trying subnet " -NoNewline
      Write-Host "$subnetKey" -ForegroundColor Yellow -NoNewline
      Write-Host " (IP: $ip) : $endpoint"
      if (Test-AdbConnect $endpoint) {
        Write-Success "Connected using remembered pairing for subnet $subnetKey"
        return $true
      }
    }
  }
  
  if ($filterSubnet -and -not $triedAny) {
    Write-Warning "No remembered pairings found for subnet $filterSubnet"
  }
  
  return $false
}

function Get-ReasonableDefaultIp {
  # Get a reasonable default IP for manual entry
  # Tries to detect subnet and use .100, falls back to common default
  $subnet = Get-CurrentSubnet
  if ($subnet) {
    return "$subnet.100"
  }
  return "192.168.1.100"
}

function Get-DefaultIpFromConfig {
  # Get the most recently used IP from config, or return default
  $cfg = Import-Config
  if ($cfg.pairings -and $cfg.pairings.Count -gt 0) {
    # Return IP from first pairing (or could use most recent)
    foreach ($subnetKey in $cfg.pairings.Keys) {
      $pairing = $cfg.pairings[$subnetKey]
      # Handle both hashtable and PSCustomObject (from JSON)
      $ip = if ($pairing -is [hashtable]) {
        $pairing['ip']
      }
      else {
        $pairing.ip
      }
      if ($ip) {
        return $ip
      }
    }
  }
  return Get-ReasonableDefaultIp
}

function Get-PairingProperty($pairing, $propertyName) {
  # Safely get a property from a pairing (handles both hashtable and PSCustomObject)
  if (-not $pairing) { return $null }
  if ($pairing -is [hashtable]) {
    return $pairing[$propertyName]
  }
  else {
    return $pairing.$propertyName
  }
}

function ConnectOrPairManual($defaultIp) {
  # Manual connection requires user interaction, skip in non-interactive mode
  if ($script:NonInteractive) {
    return $false
  }
  
  if (Test-RestartRequested) { Restart-Script }
  
  $cfg = Import-Config

  # Use default IP from config if not provided
  if ([string]::IsNullOrWhiteSpace($defaultIp)) {
    $defaultIp = Get-DefaultIpFromConfig
  }

  Write-Section "Manual Connection Mode"

  # Ask for IP/ports (with sane defaults)
  $ip = Read-WithDefault "Enter phone IP" $defaultIp
  
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Success "Using device IP: $ip"
  $subnet = Get-SubnetFromIp $ip

  # Get remembered pairing for this subnet if available
  $subnetPairing = $null
  if ($subnet -and $cfg.pairings -and $cfg.pairings[$subnet]) {
    $subnetPairing = $cfg.pairings[$subnet]
    Write-Info "Found remembered pairing for subnet $subnet"
  }

  # Prefer remembered endpoint for this subnet first
  $rememberedEndpoint = Get-PairingProperty $subnetPairing "connectEndpoint"
  if ($rememberedEndpoint) {
    Write-Info "Trying remembered endpoint: $rememberedEndpoint"
    if (Test-AdbConnect $rememberedEndpoint) { 
      Write-Success "Connected using remembered endpoint!"
      return $true 
    }
    Write-Warning "Remembered endpoint didn't connect. Falling back..."
  }

  if (Test-RestartRequested) { Restart-Script }

  # Try connect-only first using last known connect port for this subnet if present
  $rememberedConnectPort = Get-PairingProperty $subnetPairing "connectPort"
  $connectPortDefault = if ($rememberedConnectPort) { 
    "$rememberedConnectPort" 
  }
  else { 
    "5555" 
  }
  Write-Host ""
  Write-Info "On phone: Developer options -> Wireless debugging (main screen)"
  $connectPort = Read-WithDefault "Enter connect port (Wireless debugging main screen)" $connectPortDefault
  
  if (Test-RestartRequested) { Restart-Script }
  
  $endpoint = "$ip`:$connectPort"

  Write-Info "Trying connect-only: $endpoint"
  if (Test-AdbConnect $endpoint) {
    # Save pairing for this subnet
    if (-not $subnet) { $subnet = "default" }
    if (-not $cfg.pairings) { 
      $cfg | Add-Member -MemberType NoteProperty -Name 'pairings' -Value @{}
    }
    $cfg.pairings[$subnet] = @{
      ip              = $ip
      connectPort     = $connectPort
      connectEndpoint = $endpoint
    }
    Save-Config $cfg
    Write-Success "Connected successfully!"
    return $true
  }

  if (Test-RestartRequested) { Restart-Script }

  $connectPort2 = Read-HostWithRestart "Connect failed. Enter a different connect port to retry (or press Enter to proceed to pairing)"
  if (-not [string]::IsNullOrWhiteSpace($connectPort2)) {
    $endpoint2 = "$ip`:$connectPort2"
    Write-Info "Trying alternative port: $endpoint2"
    if (Test-AdbConnect $endpoint2) {
      # Save pairing for this subnet
      if (-not $subnet) { $subnet = "default" }
      if (-not $cfg.pairings) { 
        $cfg | Add-Member -MemberType NoteProperty -Name 'pairings' -Value @{}
      }
      $cfg.pairings[$subnet] = @{
        ip              = $ip
        connectPort     = $connectPort2
        connectEndpoint = $endpoint2
      }
      Save-Config $cfg
      Write-Success "Connected successfully!"
      return $true
    }
  }

  if (Test-RestartRequested) { Restart-Script }

  # If connect failed, THEN pair
  Write-Host ""
  Write-Warning "Connect-only failed. Pairing required (or your phone changed ports)."
  Write-Host ""
  Write-Info "On phone: Developer options -> Wireless debugging -> Pair device with pairing code"
  $rememberedPairPort = Get-PairingProperty $subnetPairing "pairPort"
  $pairPortDefault = if ($rememberedPairPort) {
    "$rememberedPairPort"
  }
  else {
    ""
  }
  $pairPort = if ($pairPortDefault) {
    Read-WithDefault "Enter pairing port (Pair device with pairing code screen)" $pairPortDefault
  }
  else {
    Read-HostWithRestart "Enter pairing port (Pair device with pairing code screen)"
  }
  
  if (Test-RestartRequested) { Restart-Script }
  
  $code = Read-HostWithRestart "Enter pairing code"
  
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Info "Pairing with device..."
  & adb pair "$ip`:$pairPort" $code | Out-Null

  if (Test-RestartRequested) { Restart-Script }

  # Try connect again after pairing
  Write-Info "Connecting after pairing..."
  if (Test-AdbConnect $endpoint) {
    # Save pairing for this subnet
    if (-not $subnet) { $subnet = "default" }
    if (-not $cfg.pairings) { 
      $cfg | Add-Member -MemberType NoteProperty -Name 'pairings' -Value @{}
    }
    $cfg.pairings[$subnet] = @{
      ip              = $ip
      connectPort     = $connectPort
      connectEndpoint = $endpoint
      pairPort        = $pairPort
    }
    Save-Config $cfg
    Write-Success "Connected successfully!"
    return $true
  }

  return $false
}

function Test-DesktopShortcuts {
  # Skip in non-interactive mode
  if ($script:NonInteractive) {
    return
  }
  
  if (Test-RestartRequested) { Restart-Script }
  
  # Get desktop path
  $desktopPath = [Environment]::GetFolderPath("Desktop")
  if (-not (Test-Path $desktopPath)) {
    return
  }

  # Get script directory and paths
  $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.PSCommandPath }
  $vbsPath = Join-Path $scriptDir "phone-remote.vbs"
  $ps1Path = Join-Path $scriptDir "phone-remote.ps1"
  $powershellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
  
  # Look for icon file
  $iconPath = Join-Path $scriptDir "phone-remote.ico"
  if (-not (Test-Path $iconPath)) {
    $iconPath = $null
  }

  # Check if shortcuts exist
  $shortcut1Path = Join-Path $desktopPath "Phone Remote.lnk"
  $shortcut2Path = Join-Path $desktopPath "Phone Remote (Interactive).lnk"
  
  $shortcut1Exists = Test-Path $shortcut1Path
  $shortcut2Exists = Test-Path $shortcut2Path

  # If both exist and icon is set, check if we need to update icons
  if ($shortcut1Exists -and $shortcut2Exists -and $iconPath) {
    $shell = New-Object -ComObject WScript.Shell
    $needsUpdate = $false
    
    # Check if shortcuts need icon update
    try {
      $shortcut1 = $shell.CreateShortcut($shortcut1Path)
      if ([string]::IsNullOrWhiteSpace($shortcut1.IconLocation) -or $shortcut1.IconLocation -ne $iconPath) {
        $needsUpdate = $true
      }
    }
    catch { $needsUpdate = $true }
    
    if (-not $needsUpdate) {
      try {
        $shortcut2 = $shell.CreateShortcut($shortcut2Path)
        if ([string]::IsNullOrWhiteSpace($shortcut2.IconLocation) -or $shortcut2.IconLocation -ne $iconPath) {
          $needsUpdate = $true
        }
      }
      catch { $needsUpdate = $true }
    }
    
    # If icons are already set correctly, nothing to do
    if (-not $needsUpdate) {
      return
    }
  }

  # Prompt user if any are missing or need update
  if (-not ($shortcut1Exists -and $shortcut2Exists)) {
    Write-Host ""
    Write-Section "Desktop Shortcuts"
    Write-Info "Some desktop shortcuts are missing:"
    if (-not $shortcut1Exists) {
      Write-Host "  - Phone Remote" -ForegroundColor Yellow
    }
    if (-not $shortcut2Exists) {
      Write-Host "  - Phone Remote (Interactive)" -ForegroundColor Yellow
    }
    Write-Host ""
    
    $response = Read-HostWithRestart "Would you like to create them? (Y/n)"

    if (Test-RestartRequested) { Restart-Script }

    if ($response -match '^[Nn]') {
      Write-Info "Skipping shortcut creation."
      return
    }
  }

  # Create or update shortcuts
  $shell = New-Object -ComObject WScript.Shell

  if (-not $shortcut1Exists) {
    try {
      $shortcut = $shell.CreateShortcut($shortcut1Path)
      $shortcut.TargetPath = $powershellExe
      $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ps1Path`" -NonInteractive"
      $shortcut.WorkingDirectory = $scriptDir
      $shortcut.Description = "Phone Remote - Wireless Android Control"
      if ($iconPath) {
        $shortcut.IconLocation = $iconPath
      }
      $shortcut.Save()
      Write-Success "Created shortcut: Phone Remote"
    }
    catch {
      Write-Warning "Failed to create 'Phone Remote' shortcut: $_"
    }
  }
  elseif ($iconPath) {
    # Update existing shortcut with icon and ensure it points to PowerShell (for taskbar pinning)
    try {
      $shortcut = $shell.CreateShortcut($shortcut1Path)
      # Update to PowerShell if it's still pointing to VBScript (for taskbar pinning compatibility)
      if ($shortcut.TargetPath -like "*.vbs" -or $shortcut.TargetPath -like "*wscript.exe*") {
        $shortcut.TargetPath = $powershellExe
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ps1Path`" -NonInteractive"
        $shortcut.WorkingDirectory = $scriptDir
      }
      $shortcut.IconLocation = $iconPath
      $shortcut.Save()
      Write-Success "Updated shortcut: Phone Remote"
    }
    catch {
      Write-Warning "Failed to update 'Phone Remote' shortcut: $_"
    }
  }

  if (-not $shortcut2Exists) {
    try {
      $shortcut = $shell.CreateShortcut($shortcut2Path)
      $shortcut.TargetPath = $powershellExe
      $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ps1Path`""
      $shortcut.WorkingDirectory = $scriptDir
      $shortcut.Description = "Phone Remote (Interactive) - Wireless Android Control with Console"
      if ($iconPath) {
        $shortcut.IconLocation = $iconPath
      }
      $shortcut.Save()
      Write-Success "Created shortcut: Phone Remote (Interactive)"
    }
    catch {
      Write-Warning "Failed to create 'Phone Remote (Interactive)' shortcut: $_"
    }
  }
  elseif ($iconPath) {
    # Update existing shortcut with icon
    try {
      $shortcut = $shell.CreateShortcut($shortcut2Path)
      $shortcut.IconLocation = $iconPath
      $shortcut.Save()
      Write-Success "Updated icon for shortcut: Phone Remote (Interactive)"
    }
    catch {
      Write-Warning "Failed to update 'Phone Remote (Interactive)' shortcut icon: $_"
    }
  }
}



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

adb start-server | Out-Null

if (Test-RestartRequested) { Restart-Script }

Show-Banner

Write-Section "Discovering Devices"
Write-Info "Discovering Wireless Debugging services via mDNS..."
Write-Info "(Press 'r' at any time to restart)" -ForegroundColor DarkGray
$all = Get-MdnsServices

if (Test-RestartRequested) { Restart-Script }

# Filter to pairing/connect services
$pairing = @($all | Where-Object { $_ -match "_adb-tls-pairing" })
$connect = @($all | Where-Object { $_ -match "_adb-tls-connect" })

$useMdns = $true

# "Doesn't look good" criteria:
# - No services at all
# - Missing either pairing or connect group
# - Too many services on both sides (likely stale/other devices) and user doesn't pick one
if ($all.Count -eq 0) { $useMdns = $false }
if ($pairing.Count -eq 0 -or $connect.Count -eq 0) { $useMdns = $false }

if ($useMdns) {
  # Let user choose if multiple; blank selection triggers manual fallback
  $pairService = Select-Service $pairing "Pairing (_adb-tls-pairing)"
  if (-not $pairService) { $useMdns = $false }

  if ($useMdns) {
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
      # Refresh connect list after pairing
      $all2 = Get-MdnsServices
      
      if (Test-RestartRequested) { Restart-Script }
      
      $connect2 = @($all2 | Where-Object { $_ -match "_adb-tls-connect" })
      if ($connect2.Count -eq 0) {
        $useMdns = $false
      }
      else {
        $connService = Select-Service $connect2 "Connect (_adb-tls-connect)"
        if (-not $connService) { $useMdns = $false }
        else {
          if (Test-RestartRequested) { Restart-Script }
          
          # Extract and print IP from connect service
          $connIp = if ($connService -match '^(.+?):') { $matches[1] } else { "N/A" }
          Write-Success "Connecting to device IP: $connIp"
          adb connect $connService
        }
      }
    }
  }
}

if (-not $useMdns) {
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Warning "mDNS discovery didn't look usable."
  Write-Host ""
  
  # Try remembered pairings first
  if (Connect-RememberedPairings) {
    if (Test-RestartRequested) { Restart-Script }
    Write-Success "Successfully connected using remembered pairing."
  }
  else {
    if (Test-RestartRequested) { Restart-Script }
    Write-Warning "No remembered pairings worked. Falling back to manual mode."
    $defaultIp = Get-DefaultIpFromConfig
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
