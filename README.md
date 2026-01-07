# Windows Android Remote

Do you dock your phone at your office or home workspace and wish you could just control it with your mouse and keyboard?

Have you looked at the tools landscape and determined they all look either expensive or a pain to use or usually both?

Windows Android Remote is a PowerShell wrapper script for [scrcpy](https://github.com/Genymobile/scrcpy) that lets it do the heavy lifting of wireless connection, screen mirroring, and input forwarding.

The script then handles all the shitty UX that comes with using any great OSS CLI program.

## Features

- 🔍 **Automatic Device Discovery**: Uses mDNS to discover Android devices with Wireless Debugging enabled
- 🔄 **Smart Pairing**: Automatically handles device pairing and connection
- 💾 **Connection Memory**: Remembers pairings on a per subnet basis for quick reconnection
- 🎯 **Fallback Support**: Falls back to manual IP/port entry if mDNS discovery fails
- 📦 **Auto-Install Dependencies**: Automatically installs missing dependencies (ADB, scrcpy) via winget
- 🖥️ **Remote Control**: Launches scrcpy with optimized settings (UHID keyboard, SDK mouse)
- ⚡ **Non-Interactive Mode**: Skips optional steps and prompts for faster automatic connections
- 🔄 **Smart Re-launch**: Automatically switches to interactive mode if connection fails in non-interactive mode

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Android device with Developer Options enabled
- Wireless Debugging enabled on your Android device
- Both devices on the same network (or compatible network configuration)

## Installation

1. Clone or download this repository
2. Ensure you have Windows Package Manager (winget) installed (usually pre-installed on Windows 11)
   - If not available, install from: https://aka.ms/getwinget

The script will automatically check for and install missing dependencies (`adb` and `scrcpy`) on first run.

## Usage

### First-Run Setup

1. On your Android device:

   - Enable Developer Options (tap Build Number 7 times in Settings → About Phone)
   - Enable Wireless Debugging in Developer Options
   - Note: You'll need the pairing code and ports shown on the Wireless Debugging screen

2. Run the script:

   - Double click `First Run` shortcut
   - Follow the prompts
   - If discovery works, you'll be prompted for the pairing code
   - If discovery fails, you'll enter the IP and ports manually

### Run again

The proper shortcuts are now installed and your phone is paired. You can add the shortcut from your desktop to your start menu. It will silently re-connect or if it can't find a saved connection it will restart in interactive mode

### Connection Methods

The script tries multiple methods in order:

1. **mDNS Discovery** (automatic)

   - Scans for `_adb-tls-pairing` and `_adb-tls-connect` services
   - **Interactive mode**: Automatically selects if only one device is found, prompts if multiple
   - **Non-interactive mode**: Only connects if exactly one device is found, skips if multiple

2. **Remembered Pairings** (automatic)

   - Uses saved connection info for your current subnet
   - No user input required if previously paired
   - Works in both interactive and non-interactive modes

3. **Manual Entry** (fallback)
   - Enter IP address and ports manually
   - **Interactive mode only**: Requires user input for IP, ports, and pairing codes
   - **Non-interactive mode**: Skips manual entry; re-launches in interactive mode if needed
   - Useful when mDNS discovery fails or for first-time setup

### Non-Interactive Mode Behavior

When running in non-interactive mode (via `phone-remote.vbs` or `-NonInteractive` flag):

- ✅ **Skipped**: Desktop shortcut creation prompts
- ✅ **Skipped**: Dependency installation prompts (fails fast if dependencies missing)
- ✅ **Skipped**: Manual pairing/connection prompts
- ✅ **Skipped**: Multiple device selection prompts
- ✅ **Attempted**: Automatic connections using remembered pairings
- ✅ **Attempted**: Single-device mDNS connections
- 🔄 **Auto-recovery**: If no connection is established, automatically re-launches in interactive mode

This allows for quick, silent connections when your device is already set up, while gracefully falling back to interactive mode when manual setup is needed.

## Configuration

Connection settings are stored in:

```
%APPDATA%\phone-remote\config.json
```

The config file stores:

- Pairing information per subnet
- Last used IP addresses
- Connection endpoints

You can manually edit this file if needed, or delete it to reset all saved pairings.

## Troubleshooting

### "Missing required command: 'adb'"

- **Interactive mode**: The script will prompt to install automatically via winget
- **Non-interactive mode**: Script will exit with error; install manually: `winget install Google.PlatformTools`
- Or install manually: `winget install Google.PlatformTools`

### "Missing required command: 'scrcpy'"

- **Interactive mode**: The script will prompt to install automatically via winget
- **Non-interactive mode**: Script will exit with error; install manually: `winget install Genymobile.scrcpy`
- Or install manually: `winget install Genymobile.scrcpy`

### Script Re-launches in Interactive Mode

- This happens automatically in non-interactive mode when no connection can be established
- The script will attempt automatic connections first, then re-launch if needed
- This allows you to set up new devices or troubleshoot connection issues

### mDNS Discovery Not Working

- Ensure both devices are on the same network
- Check that Wireless Debugging is enabled on your Android device
- Try the manual connection mode (the script will fall back automatically)

### Connection Fails After Pairing

- Ports may have changed - try manual mode to re-enter ports
- Ensure your firewall isn't blocking ADB connections
- Verify Wireless Debugging is still enabled on your device
- Press 'r' during setup to restart and try again

### Wrong Subnet Detected

- The script detects your local subnet automatically
- If it detects the wrong subnet, manually enter the IP address when prompted
- The script will remember the correct subnet for future connections

## Credits

- Uses [Android Debug Bridge (ADB)](https://developer.android.com/tools/adb) for device connection
- Uses [scrcpy](https://github.com/Genymobile/scrcpy) for screen mirroring and control
- Icon from [Flaticon](https://www.flaticon.com/free-icons/data-transfer)
