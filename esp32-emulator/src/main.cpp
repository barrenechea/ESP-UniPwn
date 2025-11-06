/**
 * ESP32 UniTree Robot Emulator
 *
 * This emulator mimics a UniTree robot (Go2, G1, H1, B2) for security research
 * and testing purposes. It implements the BLE protocol used by UniTree robots
 * to accept WiFi configuration commands.
 *
 * For educational and authorized security testing only.
 */

#include <Arduino.h>
#include <NimBLEDevice.h>
#include "mbedtls/aes.h"
#include <vector>
#include <string>

// BLE Service and Characteristic UUIDs (from UniTree protocol)
#define SERVICE_UUID           "0000ffe0-0000-1000-8000-00805f9b34fb"
#define CHARACTERISTIC_NOTIFY  "0000ffe1-0000-1000-8000-00805f9b34fb"
#define CHARACTERISTIC_WRITE   "0000ffe2-0000-1000-8000-00805f9b34fb"

// AES Encryption constants (hardcoded in UniTree firmware)
const uint8_t AES_KEY[16] = {
    0xdf, 0x98, 0xb7, 0x15, 0xd5, 0xc6, 0xed, 0x2b,
    0x25, 0x81, 0x7b, 0x6f, 0x25, 0x54, 0x12, 0x4a
};

const uint8_t AES_IV[16] = {
    0x28, 0x41, 0xae, 0x97, 0x41, 0x9c, 0x29, 0x73,
    0x29, 0x6a, 0x0d, 0x4b, 0xdf, 0xe1, 0x9a, 0x4f
};

// Packet opcodes
#define OPCODE_REQUEST   0x52
#define OPCODE_RESPONSE  0x51

// Instructions
#define INSTR_HANDSHAKE      0x01
#define INSTR_GET_SERIAL     0x02
#define INSTR_INIT_WIFI      0x03
#define INSTR_SET_SSID       0x04
#define INSTR_SET_PASSWORD   0x05
#define INSTR_SET_COUNTRY    0x06

// Device configuration
#define DEVICE_NAME "Go2_ESP32EMU"
#define SERIAL_NUMBER "ESP32-EMULATOR-v1.0-TESTDEVICE"

// Global state
class UniTreeEmulator {
public:
    bool authenticated = false;
    String ssid = "";
    String password = "";
    String country = "";
    std::vector<uint8_t> ssidBuffer;
    std::vector<uint8_t> passwordBuffer;
    int ssidChunksReceived = 0;
    int passwordChunksReceived = 0;
    int ssidTotalChunks = 0;
    int passwordTotalChunks = 0;

    void reset() {
        authenticated = false;
        ssid = "";
        password = "";
        country = "";
        ssidBuffer.clear();
        passwordBuffer.clear();
        ssidChunksReceived = 0;
        passwordChunksReceived = 0;
        ssidTotalChunks = 0;
        passwordTotalChunks = 0;
    }
};

UniTreeEmulator emulator;
NimBLECharacteristic* pNotifyCharacteristic = nullptr;

// mbedTLS AES context
mbedtls_aes_context aes_ctx;

void initCrypto() {
    mbedtls_aes_init(&aes_ctx);
    // Set encryption key (same key is used for both encrypt and decrypt in CFB mode)
    mbedtls_aes_setkey_enc(&aes_ctx, AES_KEY, 128);
}

std::vector<uint8_t> decryptData(const uint8_t* data, size_t len) {
    std::vector<uint8_t> output(len);

    // Make a copy of IV since mbedtls modifies it
    uint8_t iv_copy[16];
    memcpy(iv_copy, AES_IV, 16);

    size_t iv_offset = 0;

    // Decrypt using AES-CFB128
    int ret = mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_DECRYPT, len,
                                       &iv_offset, iv_copy, data, output.data());

    if (ret != 0) {
        Serial.printf("ERROR: mbedTLS decryption failed: -0x%04X\n", -ret);
    }

    return output;
}

std::vector<uint8_t> encryptData(const uint8_t* data, size_t len) {
    std::vector<uint8_t> output(len);

    // Make a copy of IV since mbedtls modifies it
    uint8_t iv_copy[16];
    memcpy(iv_copy, AES_IV, 16);

    size_t iv_offset = 0;

    // Encrypt using AES-CFB128
    int ret = mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_ENCRYPT, len,
                                       &iv_offset, iv_copy, data, output.data());

    if (ret != 0) {
        Serial.printf("ERROR: mbedTLS encryption failed: -0x%04X\n", -ret);
    }

    return output;
}

// Calculate checksum (2's complement)
uint8_t calculateChecksum(const std::vector<uint8_t>& data) {
    uint32_t sum = 0;
    for (size_t i = 0; i < data.size(); i++) {
        sum += data[i];
    }
    return (-sum) & 0xFF;
}

// Validate packet checksum
bool validateChecksum(const std::vector<uint8_t>& packet) {
    if (packet.size() < 4) return false;

    uint32_t sum = 0;
    for (size_t i = 0; i < packet.size(); i++) {
        sum += packet[i];
    }
    return (sum & 0xFF) == 0;
}

// Create response packet
std::vector<uint8_t> createResponse(uint8_t instruction, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> packet;

    packet.push_back(OPCODE_RESPONSE);

    // Length = instruction + data + checksum + 2
    uint8_t length = 1 + data.size() + 1 + 2;
    packet.push_back(length);

    packet.push_back(instruction);

    for (uint8_t byte : data) {
        packet.push_back(byte);
    }

    uint8_t checksum = calculateChecksum(packet);
    packet.push_back(checksum);

    // Encrypt the packet
    auto encrypted = encryptData(packet.data(), packet.size());

    return encrypted;
}

// Print hex data for debugging
void printHex(const char* label, const uint8_t* data, size_t len) {
    Serial.printf("%s [%d bytes]: ", label, len);
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) {
            Serial.printf("\n                  ");
        }
    }
    Serial.println();
}

void printHex(const char* label, const std::vector<uint8_t>& data) {
    printHex(label, data.data(), data.size());
}

// Handle Instruction 1: Handshake/Authentication
std::vector<uint8_t> handleHandshake(const std::vector<uint8_t>& packet) {
    Serial.println("\n=== INSTRUCTION 1: HANDSHAKE ===");

    // Packet format: [0x52, len, 0x01, 0x00, 0x00, 'u','n','i','t','r','e','e', checksum]
    if (packet.size() < 12) {
        Serial.println("ERROR: Handshake packet too short");
        return createResponse(INSTR_HANDSHAKE, {0x00}); // Failure
    }

    // Extract the authentication string (should be "unitree")
    String authString = "";
    for (size_t i = 5; i < packet.size() - 1; i++) {
        authString += (char)packet[i];
    }

    Serial.printf("Auth string received: '%s'\n", authString.c_str());

    if (authString == "unitree") {
        emulator.authenticated = true;
        Serial.println("✓ Authentication SUCCESSFUL");
        return createResponse(INSTR_HANDSHAKE, {0x01}); // Success
    } else {
        emulator.authenticated = false;
        Serial.println("✗ Authentication FAILED");
        return createResponse(INSTR_HANDSHAKE, {0x00}); // Failure
    }
}

// Handle Instruction 2: Get Serial Number
std::vector<uint8_t> handleGetSerial(const std::vector<uint8_t>& packet) {
    Serial.println("\n=== INSTRUCTION 2: GET SERIAL NUMBER ===");

    if (!emulator.authenticated) {
        Serial.println("ERROR: Not authenticated");
        return createResponse(INSTR_GET_SERIAL, {0x00}); // Not authenticated
    }

    Serial.printf("Returning serial: %s\n", SERIAL_NUMBER);

    // For simplicity, send serial in one chunk
    // Format: [chunk_index, total_chunks, data...]
    std::vector<uint8_t> response;
    response.push_back(0x01); // Chunk 1
    response.push_back(0x01); // Total 1 chunk

    // Add serial number bytes
    for (char c : String(SERIAL_NUMBER)) {
        response.push_back((uint8_t)c);
    }

    return createResponse(INSTR_GET_SERIAL, response);
}

// Handle Instruction 3: Initialize WiFi
std::vector<uint8_t> handleInitWiFi(const std::vector<uint8_t>& packet) {
    Serial.println("\n=== INSTRUCTION 3: INITIALIZE WIFI ===");

    if (packet.size() < 4) {
        Serial.println("ERROR: Packet too short");
        return createResponse(INSTR_INIT_WIFI, {0x00});
    }

    uint8_t mode = packet[3];

    if (mode == 0x01) {
        Serial.println("WiFi Mode: AP (Access Point)");
    } else if (mode == 0x02) {
        Serial.println("WiFi Mode: STA (Station)");
    } else {
        Serial.printf("WiFi Mode: Unknown (0x%02X)\n", mode);
    }

    return createResponse(INSTR_INIT_WIFI, {0x01}); // Success
}

// Handle Instruction 4: Set SSID
std::vector<uint8_t> handleSetSSID(const std::vector<uint8_t>& packet) {
    Serial.println("\n=== INSTRUCTION 4: SET SSID ===");

    if (packet.size() < 5) {
        Serial.println("ERROR: Packet too short");
        return createResponse(INSTR_SET_SSID, {0x00});
    }

    uint8_t chunkIndex = packet[3];
    uint8_t totalChunks = packet[4];

    Serial.printf("Chunk %d of %d\n", chunkIndex, totalChunks);

    // Extract chunk data
    for (size_t i = 5; i < packet.size() - 1; i++) {
        emulator.ssidBuffer.push_back(packet[i]);
    }

    emulator.ssidChunksReceived++;

    if (emulator.ssidChunksReceived >= totalChunks) {
        // All chunks received - send response
        emulator.ssid = "";
        for (uint8_t byte : emulator.ssidBuffer) {
            emulator.ssid += (char)byte;
        }
        Serial.printf("✓ Complete SSID received: '%s'\n", emulator.ssid.c_str());
        emulator.ssidBuffer.clear();
        emulator.ssidChunksReceived = 0;

        // CRITICAL: Only send response for LAST chunk (matches real robot behavior)
        return createResponse(INSTR_SET_SSID, {0x01});
    } else {
        // Intermediate chunk - do NOT send response (script doesn't wait for it)
        Serial.println("  (intermediate chunk - no response sent)");
        return std::vector<uint8_t>(); // Empty = no response
    }
}

// Handle Instruction 5: Set Password
std::vector<uint8_t> handleSetPassword(const std::vector<uint8_t>& packet) {
    Serial.println("\n=== INSTRUCTION 5: SET PASSWORD ===");

    if (packet.size() < 5) {
        Serial.println("ERROR: Packet too short");
        return createResponse(INSTR_SET_PASSWORD, {0x00});
    }

    uint8_t chunkIndex = packet[3];
    uint8_t totalChunks = packet[4];

    Serial.printf("Chunk %d of %d\n", chunkIndex, totalChunks);

    // Extract chunk data
    for (size_t i = 5; i < packet.size() - 1; i++) {
        emulator.passwordBuffer.push_back(packet[i]);
    }

    emulator.passwordChunksReceived++;

    if (emulator.passwordChunksReceived >= totalChunks) {
        // All chunks received - send response
        emulator.password = "";
        for (uint8_t byte : emulator.passwordBuffer) {
            emulator.password += (char)byte;
        }
        Serial.printf("✓ Complete password received: '%s'\n", emulator.password.c_str());

        // Check for injection patterns
        if (emulator.password.indexOf(";$(") >= 0 ||
            emulator.password.indexOf("`;") >= 0 ||
            emulator.password.indexOf("&&") >= 0 ||
            emulator.password.indexOf("||") >= 0) {
            Serial.println("⚠ WARNING: COMMAND INJECTION DETECTED!");
            Serial.printf("   Injection payload: %s\n", emulator.password.c_str());
        }

        emulator.passwordBuffer.clear();
        emulator.passwordChunksReceived = 0;

        // CRITICAL: Only send response for LAST chunk (matches real robot behavior)
        return createResponse(INSTR_SET_PASSWORD, {0x01});
    } else {
        // Intermediate chunk - do NOT send response (script doesn't wait for it)
        Serial.println("  (intermediate chunk - no response sent)");
        return std::vector<uint8_t>(); // Empty = no response
    }
}

// Handle Instruction 6: Set Country Code (TRIGGER)
std::vector<uint8_t> handleSetCountry(const std::vector<uint8_t>& packet) {
    Serial.println("\n=== INSTRUCTION 6: SET COUNTRY CODE (TRIGGER) ===");

    if (packet.size() < 5) {
        Serial.println("ERROR: Packet too short");
        return createResponse(INSTR_SET_COUNTRY, {0x00});
    }

    // Extract country code
    emulator.country = "";
    for (size_t i = 4; i < packet.size() - 1; i++) {
        if (packet[i] != 0x00) {
            emulator.country += (char)packet[i];
        }
    }

    Serial.printf("Country code: '%s'\n", emulator.country.c_str());
    Serial.println("\n╔═══════════════════════════════════════════════════════════╗");
    Serial.println("║           WIFI CONFIGURATION TRIGGERED                    ║");
    Serial.println("╚═══════════════════════════════════════════════════════════╝");
    Serial.printf("  SSID:     %s\n", emulator.ssid.c_str());
    Serial.printf("  Password: %s\n", emulator.password.c_str());
    Serial.printf("  Country:  %s\n", emulator.country.c_str());
    Serial.println("───────────────────────────────────────────────────────────");

    // Simulate the vulnerable command execution
    String simulatedCommand = "sudo sh /unitree/module/network_manager/upper_bluetooth/hostapd_restart.sh \""
                            + emulator.ssid + " " + emulator.password + "\"";
    Serial.println("\n[SIMULATION] Would execute command:");
    Serial.printf("  %s\n\n", simulatedCommand.c_str());

    // Parse what would actually execute if this were real
    if (emulator.password.indexOf(";$(") >= 0) {
        int start = emulator.password.indexOf(";$(") + 3;
        int end = emulator.password.indexOf(");", start);
        if (end > start) {
            String injectedCmd = emulator.password.substring(start, end);
            Serial.println("╔═══════════════════════════════════════════════════════════╗");
            Serial.println("║     ⚠ INJECTED COMMAND WOULD EXECUTE (ROOT):             ║");
            Serial.println("╚═══════════════════════════════════════════════════════════╝");
            Serial.printf("  >>> %s <<<\n", injectedCmd.c_str());
            Serial.println("───────────────────────────────────────────────────────────\n");
        }
    }

    return createResponse(INSTR_SET_COUNTRY, {0x01}); // Success
}

// Process received packet
void processPacket(const std::vector<uint8_t>& decrypted) {
    printHex("Decrypted packet", decrypted);

    // Validate packet structure
    if (decrypted.size() < 4) {
        Serial.println("ERROR: Packet too short");
        return;
    }

    uint8_t opcode = decrypted[0];
    uint8_t length = decrypted[1];
    uint8_t instruction = decrypted[2];

    if (opcode != OPCODE_REQUEST) {
        Serial.printf("ERROR: Invalid opcode 0x%02X (expected 0x52)\n", opcode);
        return;
    }

    if (length != decrypted.size()) {
        Serial.printf("WARNING: Length mismatch (header=%d, actual=%d)\n", length, decrypted.size());
    }

    if (!validateChecksum(decrypted)) {
        Serial.println("ERROR: Checksum validation failed");
        return;
    }

    Serial.printf("✓ Valid packet - Instruction: 0x%02X\n", instruction);

    // Process instruction
    std::vector<uint8_t> response;

    switch (instruction) {
        case INSTR_HANDSHAKE:
            response = handleHandshake(decrypted);
            break;
        case INSTR_GET_SERIAL:
            response = handleGetSerial(decrypted);
            break;
        case INSTR_INIT_WIFI:
            response = handleInitWiFi(decrypted);
            break;
        case INSTR_SET_SSID:
            response = handleSetSSID(decrypted);
            break;
        case INSTR_SET_PASSWORD:
            response = handleSetPassword(decrypted);
            break;
        case INSTR_SET_COUNTRY:
            response = handleSetCountry(decrypted);
            break;
        default:
            Serial.printf("ERROR: Unknown instruction 0x%02X\n", instruction);
            return;
    }

    // Send response
    if (pNotifyCharacteristic && response.size() > 0) {
        printHex("Sending response", response);

        pNotifyCharacteristic->setValue(response.data(), response.size());
        pNotifyCharacteristic->notify();

        Serial.println("✓ Response sent\n");

        // Small delay to ensure notification is sent
        delay(10);
    } else {
        if (!pNotifyCharacteristic) {
            Serial.println("✗ ERROR: Notify characteristic is NULL!\n");
        }
        if (response.size() == 0) {
            Serial.println("✗ ERROR: Response is empty!\n");
        }
    }
}

// BLE Callbacks
class ServerCallbacks: public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) {
        Serial.println("\n╔═══════════════════════════════════════════════════════════╗");
        Serial.println("║                  CLIENT CONNECTED                         ║");
        Serial.println("╚═══════════════════════════════════════════════════════════╝\n");
        Serial.printf("[DEBUG] Connection established\n");
    }

    void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) {
        Serial.println("\n╔═══════════════════════════════════════════════════════════╗");
        Serial.println("║                 CLIENT DISCONNECTED                       ║");
        Serial.println("╚═══════════════════════════════════════════════════════════╝\n");
        Serial.printf("[DEBUG] Disconnect reason: %d\n", reason);
        emulator.reset();

        // Small delay to ensure clean disconnect
        delay(100);

        // Restart advertising with previous configuration
        NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
        if (pAdvertising->start(0)) {
            Serial.println("✓ Advertising restarted successfully\n");
        } else {
            Serial.println("✗ Failed to restart advertising\n");
        }
    }
};

// Characteristic Callbacks
class CharacteristicCallbacks: public NimBLECharacteristicCallbacks {
public:
    CharacteristicCallbacks() {
        Serial.println("[DEBUG] CharacteristicCallbacks constructor called");
    }

    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) {
        Serial.println("\n[DEBUG] ========================================");
        Serial.println("[DEBUG] onWrite callback triggered!");
        Serial.println("[DEBUG] ========================================\n");

        std::string value = pCharacteristic->getValue();
        Serial.printf("[DEBUG] Received data length: %d\n", value.length());

        if (value.length() > 0) {
            Serial.println("\n───────────────────────────────────────────────────────────");
            Serial.printf("Received %d bytes on write characteristic\n", value.length());
            printHex("Encrypted data", (const uint8_t*)value.data(), value.length());

            // Decrypt the data
            auto decrypted = decryptData((const uint8_t*)value.data(), value.length());

            // Process the packet
            processPacket(decrypted);
        } else {
            Serial.println("[DEBUG] Received empty data!");
        }
    }

    void onRead(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) {
        Serial.println("\n[DEBUG] onRead callback triggered (unexpected)!");
    }

    void onStatus(NimBLECharacteristic* pCharacteristic, int code) {
        Serial.printf("\n[DEBUG] onStatus callback: code=%d\n", code);
    }

    void onSubscribe(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo, uint16_t subValue) {
        Serial.printf("\n[DEBUG] onSubscribe callback: subValue=%d\n", subValue);
    }
};

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("\n\n");
    Serial.println("╔═══════════════════════════════════════════════════════════╗");
    Serial.println("║         ESP32 UniTree Robot Emulator v1.0                 ║");
    Serial.println("║                                                           ║");
    Serial.println("║  For security research and educational purposes only      ║");
    Serial.println("╚═══════════════════════════════════════════════════════════╝");
    Serial.println();

    // Initialize crypto
    initCrypto();
    Serial.println("✓ AES-CFB128 initialized (mbedTLS)");

    // Initialize BLE
    NimBLEDevice::init(DEVICE_NAME);
    Serial.printf("✓ BLE device initialized: %s\n", DEVICE_NAME);

    // Create BLE Server
    NimBLEServer* pServer = NimBLEDevice::createServer();
    pServer->setCallbacks(new ServerCallbacks());

    // Create BLE Service
    NimBLEService* pService = pServer->createService(SERVICE_UUID);

    // Create Notify Characteristic
    pNotifyCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_NOTIFY,
        NIMBLE_PROPERTY::NOTIFY
    );
    Serial.printf("✓ Notify characteristic: %s\n", CHARACTERISTIC_NOTIFY);

    // Create Write Characteristic
    NimBLECharacteristic* pWriteCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_WRITE,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR
    );
    Serial.printf("✓ Write characteristic: %s\n", CHARACTERISTIC_WRITE);

    // Set callbacks for write characteristic
    CharacteristicCallbacks* pCallbacks = new CharacteristicCallbacks();
    pWriteCharacteristic->setCallbacks(pCallbacks);

    Serial.printf("✓ Callbacks registered for write characteristic\n");

    // Start the service
    pService->start();
    Serial.println("✓ BLE service started");

    // Configure advertising
    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();

    // Set the device name in advertising data (critical for discovery)
    // BLE advertising data has 31-byte limit, so we keep it minimal
    NimBLEAdvertisementData advertisementData;
    advertisementData.setName(DEVICE_NAME);  // 14 bytes (1+1+12)
    advertisementData.setFlags(BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP);  // 3 bytes
    // Total: 17 bytes - well within 31-byte limit
    pAdvertising->setAdvertisementData(advertisementData);

    // Set scan response data to include device name for compatibility
    // Service UUID is discovered via GATT, not advertised (saves space)
    NimBLEAdvertisementData scanResponseData;
    scanResponseData.setName(DEVICE_NAME);
    pAdvertising->setScanResponseData(scanResponseData);

    // Set advertising interval (units of 0.625ms)
    // 160 = 100ms, faster discovery while not draining battery too fast
    pAdvertising->setMinInterval(160);  // 100ms
    pAdvertising->setMaxInterval(320); // 200ms

    // Start advertising with duration 0 = advertise forever
    bool success = pAdvertising->start(0);

    if (success) {
        Serial.println("✓ BLE advertising started");
        Serial.println("\n╔═══════════════════════════════════════════════════════════╗");
        Serial.println("║              EMULATOR READY - WAITING FOR CLIENTS         ║");
        Serial.println("╚═══════════════════════════════════════════════════════════╝");
        Serial.println("\nAdvertising Configuration:");
        Serial.printf("  - Device Name:     %s\n", DEVICE_NAME);
        Serial.printf("  - Serial Number:   %s\n", SERIAL_NUMBER);
        Serial.printf("  - Service UUID:    %s\n", SERVICE_UUID);
        Serial.printf("  - Advertising:     Connectable & Scannable\n");
        Serial.printf("  - Adv Interval:    100-200ms\n");
        Serial.println();
    } else {
        Serial.println("✗✗✗ BLE ADVERTISING FAILED TO START! ✗✗✗");
        Serial.println("Check Bluetooth is enabled and not in use.");
        Serial.println();
    }
}

void loop() {
    // Nothing to do here, BLE callbacks handle everything
    delay(1000);
}
