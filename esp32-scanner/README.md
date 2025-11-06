# ESP32 Unitree Device Scanner

Automatically scans for Unitree robots (Go2, G1, H1, B2, X1) via BLE, extracts their serial numbers, and optionally configures WiFi. All data is stored in non-volatile storage (NVS) with MAC address + serial number + WiFi config.

## Features

- **Continuous Scanning**: Never stops scanning for Unitree devices (no scan interval)
- **Serial Number Extraction**: Connects to each device and extracts the serial number
- **WiFi Configuration**: Optionally configures WiFi on discovered devices (SSID, password, country)
- **Complete NVS Storage**: Stores MAC address + serial number + WiFi configuration
- **Skip Already Scanned**: Automatically skips devices that were already scanned based on MAC address
- **No Duplicates**: Uses MAC address as unique identifier to prevent duplicate scanning
- **Persistent Storage**: All data survives reboots via ESP32 NVS
- **Automatic Reconnection**: Continues scanning and connecting to new devices indefinitely
- **Debug Mode**: Optional verbose output showing all discovered BLE devices

## How It Works

1. **BLE Scanning**: Scans for BLE devices with names starting with `G1_`, `Go2_`, `B2_`, `H1_`, or `X1_`
2. **Connection**: When a Unitree device is found, connects to it
3. **Handshake**: Performs authentication handshake with "unitree" passphrase
4. **Serial Extraction**: Requests and receives the device serial number (may be chunked)
5. **WiFi Configuration** (optional): Configures WiFi with custom SSID, password, and country code
6. **NVS Storage**: Stores MAC address, serial number, and WiFi configuration in NVS
7. **Skip Logic**: On next scan, checks NVS and skips devices already scanned
8. **Repeat**: Continues scanning indefinitely, only processing new devices

## Building and Flashing

### Prerequisites

- PlatformIO CLI or PlatformIO IDE
- ESP32 development board

### Build

```bash
cd esp32-scanner
pio run
```

### Upload

```bash
pio run --target upload
```

### Monitor

```bash
pio device monitor -b 115200
```

## Configuration

Edit `src/main.cpp` to adjust scanning and WiFi settings:

### WiFi Configuration (Lines 57-60)

```cpp
#define CONFIGURE_WIFI    false   // Set to true to configure WiFi on scanned devices
#define WIFI_SSID        "YourSSID"
#define WIFI_PASSWORD    "YourPassword"
#define WIFI_COUNTRY     "US"
```

**To enable WiFi configuration:**
1. Set `CONFIGURE_WIFI` to `true`
2. Set your WiFi credentials in `WIFI_SSID` and `WIFI_PASSWORD`
3. Set your country code in `WIFI_COUNTRY` (e.g., "US", "GB", "CN")
4. Rebuild and upload

**⚠️ WARNING**: When `CONFIGURE_WIFI` is enabled, the scanner will automatically configure WiFi on **ALL** discovered Unitree devices. Only enable this for authorized testing!

### Scan Settings (Lines 50-54)

- `SCAN_DURATION`: Scan duration (default: 0 = continuous, **do not change**)
- `CONNECTION_TIMEOUT`: Max time to wait for connection (default: 15 seconds)
- `NOTIFICATION_TIMEOUT`: Max time to wait for device response (default: 10 seconds)
- `CHUNK_SIZE`: WiFi data chunk size (default: 14 bytes, **do not change**)
- `DEBUG_SCAN`: Print all discovered BLE devices (default: true, set false to reduce output)

## NVS Storage

The scanner uses ESP32's NVS (Non-Volatile Storage) to persist scanned devices across reboots.

- **Namespace**: `unitree_scan`
- **Key**: Sanitized MAC address (colons removed, e.g., `aabbccddeeff`)
- **Value Format**: `serial|ssid|password|country|configured`
  - Example: `Go2-2024-ABC-123|MyWiFi|MyPassword|US|1`

### Data Fields

Each device entry stores:
1. **MAC Address** (key): Unique identifier, used to prevent duplicate scanning
2. **Serial Number**: Device serial extracted via BLE
3. **WiFi SSID**: WiFi network name (if configured)
4. **WiFi Password**: WiFi password (if configured)
5. **Country Code**: WiFi country code (if configured)
6. **Configured Flag**: `1` if WiFi was configured, `0` otherwise

### Clearing NVS

To clear all scanned devices and start fresh, uncomment this line in `setup()`:

```cpp
clearAllScannedDevices();
```

Then reflash the device.

### Reading NVS Data

You can view stored data via serial monitor when devices are skipped:

```
[!] Device already scanned - SKIPPING
    Stored serial: Go2-2024-ABC-123456
    WiFi configured: MyHomeWiFi
```

## Serial Output Example

### With WiFi Configuration Disabled (default)

```
╔═══════════════════════════════════════════════════════════╗
║        ESP32 Unitree Device Scanner v2.0                  ║
║                                                           ║
║  Automatically scans for Unitree robots, extracts serial  ║
║  numbers, and optionally configures WiFi. Stores all     ║
║  data in NVS for persistence across reboots.             ║
║                                                           ║
║  For security research and educational purposes only      ║
╚═══════════════════════════════════════════════════════════╝

[+] AES-CFB128 initialized
[+] NVS storage initialized
[+] BLE initialized
[+] BLE power set to maximum

[*] Configuration:
    WiFi Configuration: DISABLED
    Scan Mode: CONTINUOUS
    Debug Scan Output: ENABLED
    Connection Timeout: 15000 ms

[+] Scanner ready!

╔═══════════════════════════════════════════════════════════╗
║         STARTING CONTINUOUS SCAN FOR UNITREE DEVICES      ║
╚═══════════════════════════════════════════════════════════╝
Looking for: G1_*, Go2_*, B2_*, H1_*, X1_*
Scan mode: CONTINUOUS (will never stop)

[+] Continuous scan started successfully
[*] Waiting for Unitree devices...

[DEBUG] Device found: 'iPhone' MAC: aa:11:22:33:44:55 RSSI: -65 dBm
[DEBUG] Device found: '' MAC: bb:22:33:44:55:66 RSSI: -78 dBm

[!] Unitree device found: Go2_ABC123
    MAC: aa:bb:cc:dd:ee:ff, RSSI: -45 dBm

╔═══════════════════════════════════════════════════════════╗
║  Connecting to: Go2_ABC123                                ║
╚═══════════════════════════════════════════════════════════╝
MAC Address: aa:bb:cc:dd:ee:ff
[*] Connecting...
[+] Connected successfully
[+] Service found
[+] Characteristics found
[+] Subscribed to notifications

[*] Sending handshake...
[+] Notification received: 8 bytes
[+] Handshake successful

[*] Requesting serial number...
[+] Serial chunk 1/1 received
[+] Complete serial number: Go2-2024-ABC-123456

╔═══════════════════════════════════════════════════════════╗
║                  SERIAL EXTRACTED!                        ║
╚═══════════════════════════════════════════════════════════╝
Device:       Go2_ABC123
MAC Address:  aa:bb:cc:dd:ee:ff
Serial:       Go2-2024-ABC-123456
───────────────────────────────────────────────────────────

[+] Saved to NVS: aa:bb:cc:dd:ee:ff
    Serial: Go2-2024-ABC-123456
[*] Scan restarted

[DEBUG] Device found: 'SomeOtherDevice' MAC: cc:dd:ee:ff:00:11 RSSI: -72 dBm
[*] Scanner running... (devices scanned: 1)
```

### With WiFi Configuration Enabled

When `CONFIGURE_WIFI` is set to `true`, additional output appears:

```
[*] Configuration:
    WiFi Configuration: ENABLED
    WiFi SSID: MyHomeWiFi
    WiFi Country: US
    [!] WiFi will be configured on all scanned devices
    Scan Mode: CONTINUOUS
    Debug Scan Output: ENABLED
    Connection Timeout: 15000 ms

...

[*] Configuring WiFi on device...
[*] Initializing WiFi (STA mode)...
[+] WiFi initialized
[*] Sending SSID: MyHomeWiFi
[+] SSID set successfully
[*] Sending password...
[+] Password set successfully
[*] Setting country code: US
[+] Country code set successfully

[+] WiFi configuration complete!
[+] Saved to NVS: aa:bb:cc:dd:ee:ff
    Serial: Go2-2024-ABC-123456
    WiFi: MyHomeWiFi (configured)
```

## Security Notice

This tool is designed for:
- **Authorized security testing** and penetration testing engagements
- **Educational purposes** to understand BLE security
- **Security research** on IoT devices
- **Defensive security** applications

**Do NOT use this tool for:**
- Unauthorized access to devices you don't own
- Malicious purposes
- Privacy violations

## Protocol Details

The scanner implements the Unitree BLE protocol:

1. **Service UUID**: `0000ffe0-0000-1000-8000-00805f9b34fb`
2. **Notify Characteristic**: `0000ffe1-0000-1000-8000-00805f9b34fb`
3. **Write Characteristic**: `0000ffe2-0000-1000-8000-00805f9b34fb`
4. **Encryption**: AES-CFB128 with hardcoded key and IV
5. **Handshake**: Sends "unitree" string for authentication
6. **Serial Request**: Instruction 0x02, receives chunked response

## Troubleshooting

### No devices found
- Ensure Unitree devices are powered on and BLE is enabled
- Check that you're within BLE range (typically <10m)
- Verify device names match the expected patterns (G1_*, Go2_*, B2_*, H1_*, X1_*)
- Enable `DEBUG_SCAN` to see all BLE devices being discovered
- Check serial monitor for `[DEBUG]` lines showing discovered devices

### Testing with esp32-emulator
To test the scanner with the included emulator:
1. Flash the emulator to one ESP32: `cd ../esp32-emulator && pio run --target upload`
2. Flash the scanner to another ESP32: `cd ../esp32-scanner && pio run --target upload`
3. Power both devices
4. Watch the scanner's serial output - it should discover "Go2_ESP32EMU"
5. The emulator will log the connection and serial extraction

### Connection fails
- Try increasing `CONNECTION_TIMEOUT`
- Check that the device isn't already connected to another client
- Verify the device is advertising connectable packets

### Serial extraction fails
- Increase `NOTIFICATION_TIMEOUT`
- Check serial monitor for error messages
- Verify the device implements the standard Unitree protocol

### NVS errors
- Ensure NVS partition is properly configured in PlatformIO
- Try clearing NVS with `clearAllScannedDevices()`
- Check available flash memory

## License

For educational and authorized security testing only.
