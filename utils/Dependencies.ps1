# Dependency management utilities for phone-remote.ps1
# Handles checking and installing required dependencies

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
