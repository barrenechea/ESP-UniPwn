# Scanner Web UI

Minimal React dashboard for supervising the ESP32 scanner: link over Web Bluetooth, watch session status, and browse the device archive stored on the microcontroller.

## Highlights
- Connects to the ESP-UniPwn scanner service and syncs the MAC/serial history.
- Shows live status, manual refresh controls, and BLE capability hints.
- Builds with Vite + TypeScript for quick iteration or static hosting.

## Quick start
1. `npm install`
2. `npm run dev` to launch locally, or `npm run build` for a production bundle.
3. Serve the app over HTTPS (Chrome/Edge) before pairing with the scanner.
