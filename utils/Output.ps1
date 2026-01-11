# Output utilities for phone-remote.ps1
# Provides formatted output functions and banner display

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
