# Network utilities for phone-remote.ps1
# Handles network diagnostics, subnet detection, and mDNS discovery

function Show-NetworkDiagnostics {
  # Show network information to help debug mDNS issues
  Write-Host ""
  Write-Info "=== Network Diagnostics ===" -ForegroundColor Cyan
  try {
    # Get local IP addresses
    $localIps = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
    Where-Object { 
      $_.IPAddress -notlike "127.*" -and 
      $_.IPAddress -notlike "169.254.*"
    } | 
    Select-Object -First 5
    
    if ($localIps) {
      Write-Info "Local IP addresses:"
      foreach ($ip in $localIps) {
        $adapter = Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -ErrorAction SilentlyContinue
        $adapterName = if ($adapter) { $adapter.Name } else { "Unknown" }
        Write-Host "  - $($ip.IPAddress) ($adapterName)" -ForegroundColor Gray
      }
    }
    
    # Check if mDNS/Bonjour service is running
    $mdnsService = Get-Service -Name "Bonjour Service" -ErrorAction SilentlyContinue
    if ($mdnsService) {
      if ($mdnsService.Status -eq "Running") {
        Write-Success "Bonjour Service (mDNS) is running"
      }
      else {
        Write-Warning "Bonjour Service (mDNS) is not running (Status: $($mdnsService.Status))"
        Write-Info "  Try: Start-Service 'Bonjour Service'" -ForegroundColor DarkGray
      }
    }
    else {
      Write-Warning "Bonjour Service not found - mDNS may not be available"
      Write-Info "  Windows 10/11 may use different mDNS implementation" -ForegroundColor DarkGray
    }
    
    # Check firewall rules for mDNS
    $mdnsFirewall = Get-NetFirewallRule -DisplayName "*mDNS*" -ErrorAction SilentlyContinue
    if (-not $mdnsFirewall) {
      $mdnsFirewall = Get-NetFirewallRule -DisplayName "*Bonjour*" -ErrorAction SilentlyContinue
    }
    if ($mdnsFirewall) {
      Write-Info "mDNS/Bonjour firewall rules found: $($mdnsFirewall.Count)"
    }
    else {
      Write-Info "No specific mDNS firewall rules found (may use default rules)"
    }
    
  }
  catch {
    Write-Warning "Could not gather all network diagnostics: $_"
  }
  Write-Host ""
}

function Get-MdnsServices {
  # Returns array of service strings, may be empty.
  # Also returns diagnostic info via reference parameter
  param([ref]$diagnostics = $null)
  
  try {
    # Use temporary files to capture stdout and stderr
    $tempDir = [System.IO.Path]::GetTempPath()
    $stdoutFile = Join-Path $tempDir "phone_remote_stdout_$([System.Guid]::NewGuid().ToString('N').Substring(0,8)).txt"
    $stderrFile = Join-Path $tempDir "phone_remote_stderr_$([System.Guid]::NewGuid().ToString('N').Substring(0,8)).txt"
    
    $stdout = @()
    $stderr = @()
    $exitCode = 0
    
    try {
      $process = Start-Process -FilePath "adb" -ArgumentList "mdns", "services" -NoNewWindow -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -Wait
      $exitCode = $process.ExitCode
      
      if (Test-Path $stdoutFile) {
        $stdout = Get-Content $stdoutFile -ErrorAction SilentlyContinue
        Remove-Item $stdoutFile -ErrorAction SilentlyContinue
      }
      if (Test-Path $stderrFile) {
        $stderr = Get-Content $stderrFile -ErrorAction SilentlyContinue
        Remove-Item $stderrFile -ErrorAction SilentlyContinue
      }
    }
    finally {
      # Cleanup temp files if they still exist
      if (Test-Path $stdoutFile) { Remove-Item $stdoutFile -ErrorAction SilentlyContinue }
      if (Test-Path $stderrFile) { Remove-Item $stderrFile -ErrorAction SilentlyContinue }
    }
    
    # Store diagnostics if requested
    if ($null -ne $diagnostics) {
      $diagnostics.Value = @{
        ExitCode  = $exitCode
        Stdout    = $stdout
        Stderr    = $stderr
        RawOutput = $stdout
      }
    }
    
    if (-not $stdout) { return @() }
    
    # Filter out ADB header line and empty lines
    # ADB outputs "List of discovered mdns services" as a header, followed by actual services
    $services = @($stdout | ForEach-Object { 
        $line = $_.ToString().Trim()
        # Skip header line and empty lines
        if ($line -and $line -ne "List of discovered mdns services") {
          $line
        }
      } | Where-Object { $_ })
    
    return $services
  }
  catch {
    if ($null -ne $diagnostics) {
      $diagnostics.Value = @{
        Error    = $_.Exception.Message
        ExitCode = -1
        Stdout   = @()
        Stderr   = @()
      }
    }
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

function Get-SubnetFromIp($ip) {
  # Extract subnet from IP (e.g., "192.168.12.185" -> "192.168.12")
  if ([string]::IsNullOrWhiteSpace($ip)) { return $null }
  $parts = $ip -split '\.'
  if ($parts.Count -ge 3) {
    return "$($parts[0]).$($parts[1]).$($parts[2])"
  }
  return $null
}

function Get-OnlineNetworkInterfaces {
  # Returns array of hashtables with interface info: IP, Subnet, AdapterName, InterfaceIndex, HasGateway
  # Only returns interfaces that are online and have valid IPs
  $interfaces = @()
  try {
    $allAdapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
    Where-Object { 
      $_.IPAddress -notlike "127.*" -and 
      $_.IPAddress -notlike "169.254.*"
    }
    
    foreach ($adapter in $allAdapters) {
      $ifIndex = $adapter.InterfaceIndex
      $netAdapter = Get-NetAdapter -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue
      
      # Skip if adapter is not up
      if ($netAdapter -and $netAdapter.Status -ne "Up") { continue }
      
      $adapterName = if ($netAdapter) { $netAdapter.Name } else { "Unknown" }
      $adapterDesc = if ($netAdapter) { $netAdapter.InterfaceDescription } else { "Unknown" }
      $ip = $adapter.IPAddress
      $subnet = Get-SubnetFromIp $ip
      
      # Check if adapter has default gateway (internet connectivity)
      $hasGateway = $false
      $routes = Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
      if ($routes) { $hasGateway = $true }
      
      # Skip VPN/virtual adapters
      if ($adapterDesc -match "VPN|TAP|Virtual|Hyper-V|VMware|VirtualBox|WSL") {
        # Still include if it has a gateway (might be legitimate)
        if (-not $hasGateway) { continue }
      }
      
      if ($subnet) {
        $interfaces += @{
          IP = $ip
          Subnet = $subnet
          AdapterName = $adapterName
          AdapterDescription = $adapterDesc
          InterfaceIndex = $ifIndex
          HasGateway = $hasGateway
        }
      }
    }
  }
  catch {
    Write-Warning "Error getting network interfaces: $_"
  }
  
  return $interfaces
}

function Get-BestInterfaceForPairing {
  # Finds the best network interface that matches a saved pairing
  # Returns hashtable with interface info and pairing info, or $null
  $cfg = Import-Config
  if (-not $cfg.pairings -or $cfg.pairings.Count -eq 0) {
    return $null
  }
  
  $onlineInterfaces = Get-OnlineNetworkInterfaces
  if ($onlineInterfaces.Count -eq 0) {
    return $null
  }
  
  # Try to find interface that matches a saved pairing subnet
  foreach ($iface in $onlineInterfaces) {
    $subnet = $iface.Subnet
    if ($cfg.pairings[$subnet]) {
      $pairing = $cfg.pairings[$subnet]
      return @{
        Interface = $iface
        Pairing = $pairing
        Subnet = $subnet
      }
    }
  }
  
  return $null
}

function Show-AdbInterfaceInfo {
  # Shows which network interfaces are available and which one matches saved pairings
  Write-Host ""
  Write-Info "=== Network Interface Analysis ===" -ForegroundColor Cyan
  
  $onlineInterfaces = Get-OnlineNetworkInterfaces
  if ($onlineInterfaces.Count -eq 0) {
    Write-Warning "No online network interfaces found"
    return
  }
  
  Write-Info "Online network interfaces:"
  foreach ($iface in $onlineInterfaces) {
    $status = if ($iface.HasGateway) { "[OK] Gateway" } else { "[--] No Gateway" }
    Write-Host "  - $($iface.IP) ($($iface.AdapterName))" -NoNewline
    Write-Host " [$($iface.Subnet)]" -ForegroundColor DarkGray -NoNewline
    Write-Host " $status" -ForegroundColor $(if ($iface.HasGateway) { "Green" } else { "DarkGray" })
  }
  
  $bestMatch = Get-BestInterfaceForPairing
  if ($bestMatch) {
    Write-Host ""
    Write-Success "Found matching interface with saved pairing:"
    Write-Host "  Interface: $($bestMatch.Interface.IP) ($($bestMatch.Interface.AdapterName))" -ForegroundColor Gray
    Write-Host "  Subnet: $($bestMatch.Subnet)" -ForegroundColor Gray
    $pairingIp = Get-PairingProperty $bestMatch.Pairing "ip"
    $pairingEndpoint = Get-PairingProperty $bestMatch.Pairing "connectEndpoint"
    if ($pairingIp) {
      Write-Host "  Saved pairing IP: $pairingIp" -ForegroundColor Gray
    }
    if ($pairingEndpoint) {
      Write-Host "  Saved endpoint: $pairingEndpoint" -ForegroundColor Gray
    }
  }
  else {
    Write-Host ""
    Write-Info "No saved pairings match online interfaces"
  }
  
  Write-Host ""
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
