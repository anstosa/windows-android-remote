# Configuration management utilities for phone-remote.ps1
# Handles config file operations and pairing management

function Get-ConfigPath {
  $dir = Join-Path $env:APPDATA "phone-remote"
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  return (Join-Path $dir "config.json")
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
