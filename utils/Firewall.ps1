# Firewall utilities for phone-remote.ps1
# Handles firewall rule creation and management

function Test-AndCreate-FirewallRules {
  # Check and create firewall rules for ADB wireless debugging
  # Requires admin privileges to create firewall rules
  
  Write-Host ""
  Write-Section "Checking Firewall Rules"
  
  $rulesCreated = $false
  $needsElevation = $false
  
  # Check if running as administrator
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  
  if (-not $isAdmin) {
    Write-Warning "Administrator privileges required to create firewall rules."
    Write-Info "Firewall rules will be checked but not created automatically."
    Write-Info "If connections fail, run this script as Administrator to create firewall rules."
    Write-Host ""
    $needsElevation = $true
  }
  
  # Check for mDNS firewall rule (port 5353 UDP)
  Write-Info "Checking mDNS firewall rule (port 5353 UDP)..."
  $mdnsRule = Get-NetFirewallRule -DisplayName "Phone Remote - mDNS" -ErrorAction SilentlyContinue
  if (-not $mdnsRule) {
    Write-Warning "mDNS firewall rule not found."
    if ($isAdmin) {
      try {
        New-NetFirewallRule -DisplayName "Phone Remote - mDNS" `
          -Description "Allows mDNS (multicast DNS) for Android wireless debugging discovery" `
          -Direction Inbound `
          -Protocol UDP `
          -LocalPort 5353 `
          -Action Allow `
          -Profile Domain, Private, Public `
          -ErrorAction Stop | Out-Null
        Write-Success "Created mDNS firewall rule (port 5353 UDP)"
        $rulesCreated = $true
      }
      catch {
        Write-Warning "Failed to create mDNS firewall rule: $_"
      }
    }
    else {
      Write-Info "Skipping creation (requires admin privileges)"
    }
  }
  else {
    Write-Success "mDNS firewall rule already exists"
  }
  
  # Check for ADB firewall rule (for ADB server and connections)
  Write-Info "Checking ADB firewall rule..."
  $adbRule = Get-NetFirewallRule -DisplayName "Phone Remote - ADB" -ErrorAction SilentlyContinue
  if (-not $adbRule) {
    Write-Warning "ADB firewall rule not found."
    if ($isAdmin) {
      try {
        # Try to get ADB executable path
        $adbPath = $null
        try {
          $adbCmd = Get-Command adb -ErrorAction Stop
          $adbPath = $adbCmd.Source
        }
        catch {
          # ADB might not be in PATH yet, try common locations
          $commonPaths = @(
            "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
            "$env:ProgramFiles\Android\android-sdk\platform-tools\adb.exe",
            "$env:USERPROFILE\AppData\Local\Android\Sdk\platform-tools\adb.exe"
          )
          foreach ($path in $commonPaths) {
            if (Test-Path $path) {
              $adbPath = $path
              break
            }
          }
        }
        
        if ($adbPath -and (Test-Path $adbPath)) {
          # Create program-based rule
          New-NetFirewallRule -DisplayName "Phone Remote - ADB" `
            -Description "Allows Android Debug Bridge (ADB) wireless debugging connections" `
            -Direction Inbound `
            -Protocol TCP `
            -Program $adbPath `
            -Action Allow `
            -Profile Domain, Private, Public `
            -ErrorAction Stop | Out-Null
          Write-Success "Created ADB firewall rule (program-based)"
          $rulesCreated = $true
        }
        else {
          # Fall back to port-based rule
          throw "ADB path not found, using port-based rule"
        }
      }
      catch {
        # If program path fails, try port-based rule instead
        try {
          Write-Info "Creating port-based ADB firewall rule..."
          # ADB typically uses ports 5555-5585 for wireless debugging
          New-NetFirewallRule -DisplayName "Phone Remote - ADB" `
            -Description "Allows Android Debug Bridge (ADB) wireless debugging connections" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 5555-5585 `
            -Action Allow `
            -Profile Domain, Private, Public `
            -ErrorAction Stop | Out-Null
          Write-Success "Created ADB firewall rule (ports 5555-5585)"
          $rulesCreated = $true
        }
        catch {
          Write-Warning "Failed to create ADB firewall rule: $_"
        }
      }
    }
    else {
      Write-Info "Skipping creation (requires admin privileges)"
    }
  }
  else {
    Write-Success "ADB firewall rule already exists"
  }
  
  if ($rulesCreated) {
    Write-Host ""
    Write-Success "Firewall rules configured successfully!"
  }
  elseif ($needsElevation) {
    Write-Host ""
    Write-Info "To create firewall rules automatically, run this script as Administrator."
  }
  else {
    Write-Host ""
    Write-Info "All required firewall rules are in place."
  }
  Write-Host ""
}
