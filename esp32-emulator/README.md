# ESP32 UniTree Robot Emulator

A complete ESP32-based emulator that mimics UniTree robots (Go2, G1, H1, B2) for security research and testing purposes. This emulator implements the full BLE protocol used by UniTree robots, allowing you to test exploits and port scripts without needing physical hardware.

## Features

- ✅ **Full Protocol Implementation**: All 6 instructions (handshake, serial, WiFi init, SSID, password, country)
- ✅ **AES-CFB128 Encryption**: Identical crypto implementation with hardcoded keys
- ✅ **Packet Validation**: Checksum validation and proper packet structure
- ✅ **State Management**: Tracks authentication, chunked data reassembly
- ✅ **Injection Detection**: Identifies and logs command injection attempts
- ✅ **Comprehensive Logging**: Detailed serial output for debugging
- ✅ **1:1 Emulation**: Behaves identically to real UniTree robots

## Hardware Requirements

- ESP32 Development Board (ESP32-WROOM, ESP32-DevKitC, or similar)
- USB cable for programming and serial monitoring
- Computer with PlatformIO installed

## Software Requirements

- [PlatformIO](https://platformio.org/) (VSCode extension or CLI)
- Python 3.x (for running the original exploit script)

## Dependencies

The emulator uses:
- **NimBLE-Arduino 2.3.6**: Bluetooth Low Energy stack
- **mbedTLS**: Native ESP32 crypto library for AES-CFB128 encryption (hardware accelerated)

## Installation

### 1. Install PlatformIO

**VSCode Extension (Recommended):**
```bash
# Install VSCode
# Then install the PlatformIO IDE extension from the marketplace
```

**Or CLI:**
```bash
pip install platformio
```

### 2. Clone and Build

```bash
cd esp32-emulator

# Build the project
pio run

# Or in VSCode: Click "Build" in the PlatformIO toolbar
```

### 3. Flash to ESP32

```bash
# Find your ESP32's serial port
# Linux: usually /dev/ttyUSB0 or /dev/ttyACM0
# macOS: usually /dev/cu.usbserial-*
# Windows: usually COM3, COM4, etc.

# Flash the firmware
pio run --target upload

# Or in VSCode: Click "Upload" in the PlatformIO toolbar
```

### 4. Monitor Serial Output

```bash
# Open serial monitor
pio device monitor

# Or in VSCode: Click "Serial Monitor" in the PlatformIO toolbar
```

## Configuration

You can customize the emulator by editing `src/main.cpp`:

```cpp
// Change device name (line 27)
#define DEVICE_NAME "Go2_ESP32EMU"
// Options: Go2_*, G1_*, H1_*, B2_*, X1_*

// Change serial number (line 28)
#define SERIAL_NUMBER "ESP32-EMULATOR-v1.0-TESTDEVICE"
```

After making changes, rebuild and reflash:
```bash
pio run --target upload
```

## Usage

### Testing with the Original Exploit Script

1. **Start the Emulator:**
   - Flash the ESP32 and open serial monitor
   - You should see: "EMULATOR READY - WAITING FOR CLIENTS"

2. **Run the Original Script:**
   ```bash
   cd ..  # Back to ESP-UniPwn root
   python3 script.py
   ```

3. **Select the Emulator:**
   - The script will scan and find your emulator (e.g., "Go2_ESP32EMU")
   - Select it from the list

4. **Watch the Interaction:**
   - Serial monitor shows all received commands
   - Script output shows the exploit flow
   - Emulator logs command injection attempts

### Example Serial Output

```
╔═══════════════════════════════════════════════════════════╗
║                  CLIENT CONNECTED                         ║
╚═══════════════════════════════════════════════════════════╝

=== INSTRUCTION 1: HANDSHAKE ===
Auth string received: 'unitree'
✓ Authentication SUCCESSFUL

=== INSTRUCTION 2: GET SERIAL NUMBER ===
Returning serial: ESP32-EMULATOR-v1.0-TESTDEVICE

=== INSTRUCTION 3: INITIALIZE WIFI ===
WiFi Mode: STA (Station)

=== INSTRUCTION 4: SET SSID ===
Chunk 1 of 1
✓ Complete SSID received: 'TestNetwork'

=== INSTRUCTION 5: SET PASSWORD ===
Chunk 1 of 1
✓ Complete password received: '";$(reboot -f);#'
⚠ WARNING: COMMAND INJECTION DETECTED!
   Injection payload: ";$(reboot -f);#

=== INSTRUCTION 6: SET COUNTRY CODE (TRIGGER) ===
Country code: 'US'

╔═══════════════════════════════════════════════════════════╗
║           WIFI CONFIGURATION TRIGGERED                    ║
╚═══════════════════════════════════════════════════════════╝
  SSID:     TestNetwork
  Password: ";$(reboot -f);#
  Country:  US
───────────────────────────────────────────────────────────

[SIMULATION] Would execute command:
  sudo sh /unitree/module/network_manager/upper_bluetooth/hostapd_restart.sh "TestNetwork ";$(reboot -f);#"

╔═══════════════════════════════════════════════════════════╗
║     ⚠ INJECTED COMMAND WOULD EXECUTE (ROOT):             ║
╚═══════════════════════════════════════════════════════════╝
  >>> reboot -f <<<
───────────────────────────────────────────────────────────
```

## Protocol Implementation

The emulator implements the complete UniTree BLE protocol:

### BLE Service
- **Service UUID**: `0000ffe0-0000-1000-8000-00805f9b34fb`
- **Write Characteristic**: `0000ffe2-0000-1000-8000-00805f9b34fb`
- **Notify Characteristic**: `0000ffe1-0000-1000-8000-00805f9b34fb`

### Encryption
- **Library**: mbedTLS (native ESP32, hardware accelerated)
- **Algorithm**: AES-CFB128
- **Key**: `df98b715d5c6ed2b25817b6f2554124a` (hex)
- **IV**: `2841ae97419c2973296a0d4bdfe19a4f` (hex)

### Packet Format
```
Request:  [0x52, length, instruction, data..., checksum]
Response: [0x51, length, instruction, data..., checksum]
```

### Instructions
1. **0x01 - Handshake**: Authenticate with "unitree" string
2. **0x02 - Get Serial**: Return device serial number
3. **0x03 - Init WiFi**: Set WiFi mode (AP/STA)
4. **0x04 - Set SSID**: Configure network SSID (chunked)
5. **0x05 - Set Password**: Configure password (chunked, vulnerable)
6. **0x06 - Set Country**: Trigger WiFi configuration (exploit trigger)

## Troubleshooting

### ESP32 Not Found
```bash
# List available devices
pio device list

# Specify port manually
pio run --target upload --upload-port /dev/ttyUSB0
```

### Build Errors
```bash
# Clean and rebuild
pio run --target clean
pio run
```

### BLE Connection Issues
- Ensure Bluetooth is enabled on your computer
- Check that the emulator is advertising (serial monitor shows "advertising started")
- Try restarting the ESP32 (press reset button)
- Make sure no other device is connected to the emulator

### Script Can't Find Emulator
- Check device name matches a supported pattern (Go2_*, G1_*, etc.)
- Ensure ESP32 is powered and running (check serial monitor)
- Try moving the ESP32 closer to your computer
- Restart Bluetooth on your computer

## Development

### Project Structure
```
esp32-emulator/
├── platformio.ini          # PlatformIO configuration
├── src/
│   └── main.cpp           # Main emulator code
└── README.md              # This file
```

### Key Components

**`UniTreeEmulator` class**: State management
- Authentication flag
- SSID/password storage
- Chunk reassembly buffers

**Crypto functions** (using mbedTLS):
- `initCrypto()`: Initialize mbedTLS AES context
- `decryptData()`: AES-CFB128 decryption (hardware accelerated)
- `encryptData()`: AES-CFB128 encryption (hardware accelerated)
- `calculateChecksum()`: 2's complement checksum

**Packet handlers**:
- `handleHandshake()`: Process auth request
- `handleGetSerial()`: Return serial number
- `handleInitWiFi()`: Acknowledge WiFi mode
- `handleSetSSID()`: Collect SSID chunks
- `handleSetPassword()`: Collect password chunks (detects injection)
- `handleSetCountry()`: Trigger configuration (logs simulated execution)

**BLE callbacks**:
- `ServerCallbacks`: Handle connect/disconnect
- `CharacteristicCallbacks`: Process incoming writes

## Security Notes

⚠️ **For Educational and Authorized Testing Only**

This emulator is designed for:
- Security research
- Penetration testing (with authorization)
- Exploit development and testing
- Training and education

**DO NOT** use this tool for:
- Unauthorized access to devices
- Malicious purposes
- Real-world attacks without authorization

The vulnerabilities demonstrated are:
- **CVE-2025-35027, CVE-2025-60017, CVE-2025-60250, CVE-2025-60251**
- Discovered by Andreas Makris (Bin4ry) and Kevin Finisterre (h0stile)

## Porting to Other Platforms

This emulator is designed to make porting easy:

### Key Considerations

1. **Protocol Layer**: The packet handling, encryption, and instruction processing are platform-agnostic
2. **BLE Stack**: Replace NimBLE with your platform's BLE library
3. **Crypto**: Replace with platform's crypto library (OpenSSL, mbedTLS, etc.)

### Porting Checklist

- [ ] Implement BLE GATT server with correct UUIDs
- [ ] Implement AES-CFB128 with hardcoded key/IV
- [ ] Port packet parsing and checksum validation
- [ ] Port all 6 instruction handlers
- [ ] Add state management for chunked data
- [ ] Test with original script

### Example Platforms

- **Arduino (other boards)**: Modify BLE library for nRF52, etc.
- **Raspberry Pi**: Use BlueZ with Python bindings
- **Desktop**: Use BlueZ (Linux) or CoreBluetooth (macOS)
- **Mobile**: Android (BLE API) or iOS (CoreBluetooth)

## License

This tool is provided for educational and research purposes. Use responsibly and only on systems you own or have explicit authorization to test.

## Credits

- **Vulnerability Research**: Andreas Makris (Bin4ry), Kevin Finisterre (h0stile)
- **Original Exploit**: Bin4ry's Unitree Infiltration Tool v2.6
- **Emulator**: ESP32 port for testing and development

## References

- [UniTree Vulnerabilities Disclosure](https://www.zerodayinitiative.com/)
- [Original Script](../script.py)
- [Vulnerability Details](../README.md)
