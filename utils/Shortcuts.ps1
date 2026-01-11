# Desktop shortcut utilities for phone-remote.ps1
# Handles creation and management of desktop shortcuts

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
