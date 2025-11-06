# ESP-UniPwn

Toolkit for exploring Unitree BLE weaknesses without needing production robots. The projects here reproduce the vulnerable protocol, automate large-scale scans, and surface captured telemetry for analysis.

## Repository Map
- `esp32-scanner/` — ESP32 firmware that sweeps for Unitree robots, extracts serial numbers, and persists findings.
- `esp32-emulator/` — ESP32 firmware that emulates the Unitree BLE stack so exploits can be rehearsed safely.
- `scanner-web/` — Web dashboard that links to the scanner and browses the historical device archive.

## Getting Started
1. Install PlatformIO and flash either firmware project (`cd esp32-*/ && pio run --target upload`).
2. Bring the BLE node online, then use `scanner-web` (`npm install && npm run dev`) to review the collected devices.
3. See each sub-project README for configuration switches and safety notes. Keep usage to authorized research.

## Attribution & License
- Built from the research and disclosure in [Bin4ry/UniPwn](https://github.com/Bin4ry/UniPwn), reimplementing the BLE protocol on ESP32 firmware, adding a continuous scanner, and bundling a web dashboard plus helper tooling.
- Released under the [Creative Commons CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) license—retain attribution, share alike, and keep usage non-commercial.
