# Input utilities for phone-remote.ps1
# Handles user input with restart capability

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
