# Restart and interactive mode utilities for phone-remote.ps1
# Handles script restart functionality and interactive mode switching

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

function Start-InteractiveMode {
  # Re-launch the script in interactive mode
  # If we originally started non-interactive, set env var to restart non-interactive after connection
  if ($script:OriginallyNonInteractive) {
    $env:PHONE_REMOTE_RESTART_NONINTERACTIVE = "1"
  }
  
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
