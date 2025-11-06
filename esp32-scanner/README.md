# ESP32 Unitree Device Scanner

ESP32 firmware that continuously sweeps for Unitree robots and captures their serial numbers.

## Highlights
- Filters for Unitree advertising names and performs the vulnerable BLE handshake automatically.
- Stores MAC and serial in NVS so duplicates are skipped across reboots.

## Quick start
1. `pio run --target upload` — compile and flash to an ESP32 board.
2. `pio device monitor -b 115200` — watch discoveries and NVS status messages.
3. Pair the board with the web dashboard in `../scanner-web/` to browse the collected archive.

Authorised research only. Keep the firmware isolated from unintended devices.
