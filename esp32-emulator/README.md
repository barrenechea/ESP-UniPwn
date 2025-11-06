# ESP32 Unitree Emulator

Firmware for an ESP32 that mimics the Unitree Wi-Fi provisioning service, including the insecure handshake and AES-CFB128 message flow. Use it to validate tooling without risking a production robot.

## Highlights
- Emulates all known BLE instructions (handshake, serial fetch, Wi-Fi setup, trigger).
- Mirrors the real crypto parameters so exploit payloads behave identically.
- Emits concise serial logs to trace each interaction and payload.

## Quick start
1. `pio run --target upload` — build and flash to an ESP32 development board.
2. `pio device monitor` — watch handshake, serial responses, and injection attempts.
3. Adjust identifiers or canned serials in `src/main.cpp` before rebuilding if needed.

Authorised research only. Keep the firmware isolated from unintended devices.
