# Connection utilities for phone-remote.ps1
# Handles ADB connection, pairing, and device management

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

function Connect-ManualPair {
  # Manual pairing requires user interaction, skip in non-interactive mode
  if ($script:NonInteractive) {
    return $false
  }
  
  if (Test-RestartRequested) { Restart-Script }
  
  Write-Host ""
  Write-Section "Manual Pairing Mode"
  Write-Info "Using phone's Wireless debugging screen values."
  $defaultIp = Get-DefaultIpFromConfig
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
