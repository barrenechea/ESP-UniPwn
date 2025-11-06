/**
 * ESP32 Unitree Device Scanner - Bluedroid Version
 *
 * Automatically scans for Unitree robots (Go2, G1, H1, B2, X1) via BLE,
 * extracts their serial numbers and stores them in NVS.
 *
 * Using Bluedroid (standard ESP32 BLE stack) for maximum compatibility.
 */

#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEClient.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <Preferences.h>
#include "mbedtls/aes.h"
#include <map>
#include <vector>
#include "nvs_flash.h"
#include "nvs.h"

// BLE Service and Characteristic UUIDs (from Unitree protocol)
#define SERVICE_UUID           "0000ffe0-0000-1000-8000-00805f9b34fb"
#define CHARACTERISTIC_NOTIFY  "0000ffe1-0000-1000-8000-00805f9b34fb"
#define CHARACTERISTIC_WRITE   "0000ffe2-0000-1000-8000-00805f9b34fb"

// Web Dashboard Service UUIDs
#define DASHBOARD_SERVICE_UUID      "0000fff0-0000-1000-8000-00805f9b34fb"
#define DEVICE_LIST_CHAR_UUID       "0000fff1-0000-1000-8000-00805f9b34fb"
#define DEVICE_COUNT_CHAR_UUID      "0000fff2-0000-1000-8000-00805f9b34fb"

// AES Encryption constants (hardcoded in Unitree firmware)
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

// Configuration
#define HANDSHAKE_CONTENT "unitree"
#define SCAN_DURATION_SECS 5
#define CONNECTION_TIMEOUT 30000
#define NOTIFICATION_TIMEOUT 10000

// NVS storage
Preferences preferences;

// Device data structure
struct DeviceData {
    String macAddress;
    String serialNumber;
};

// AES context
mbedtls_aes_context aes_ctx;

// Scan state
bool isConnecting = false;
uint32_t devicesScanned = 0;
BLEAddress* pServerAddress = nullptr;
bool doConnect = false;
BLEClient* pClient = nullptr;

// Serial number reassembly
std::map<uint8_t, std::vector<uint8_t>> serialChunks;
uint8_t serialTotalChunks = 0;
bool serialComplete = false;
String serialNumber = "";

// BLE Server for web dashboard
BLEServer* pDashboardServer = nullptr;
BLECharacteristic* pDeviceListChar = nullptr;
BLECharacteristic* pDeviceCountChar = nullptr;

// Forward declarations
bool connectAndFetchSerial(BLEAddress address, String deviceName);
void scanForDevices();
String getAllDevicesFromNVS();
uint8_t getDeviceCountFromNVS();

// Initialize AES
void initCrypto() {
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, AES_KEY, 128);
}

// Encrypt data
std::vector<uint8_t> encryptData(const uint8_t* data, size_t len) {
    std::vector<uint8_t> output(len);
    uint8_t iv_copy[16];
    memcpy(iv_copy, AES_IV, 16);
    size_t iv_offset = 0;
    mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_ENCRYPT, len,
                             &iv_offset, iv_copy, data, output.data());
    return output;
}

// Decrypt data
std::vector<uint8_t> decryptData(const uint8_t* data, size_t len) {
    std::vector<uint8_t> output(len);
    uint8_t iv_copy[16];
    memcpy(iv_copy, AES_IV, 16);
    size_t iv_offset = 0;
    mbedtls_aes_crypt_cfb128(&aes_ctx, MBEDTLS_AES_DECRYPT, len,
                             &iv_offset, iv_copy, data, output.data());
    return output;
}

// Calculate checksum
uint8_t calculateChecksum(const std::vector<uint8_t>& data) {
    uint32_t sum = 0;
    for (uint8_t byte : data) {
        sum += byte;
    }
    return (-sum) & 0xFF;
}

// Validate checksum
bool validateChecksum(const std::vector<uint8_t>& packet) {
    if (packet.size() < 4) return false;
    uint32_t sum = 0;
    for (uint8_t byte : packet) {
        sum += byte;
    }
    return (sum & 0xFF) == 0;
}

// Create packet
std::vector<uint8_t> createPacket(uint8_t instruction, const std::vector<uint8_t>& data_bytes) {
    std::vector<uint8_t> instruction_data;
    instruction_data.push_back(instruction);
    instruction_data.insert(instruction_data.end(), data_bytes.begin(), data_bytes.end());

    uint8_t length = instruction_data.size() + 3;
    std::vector<uint8_t> full_data;
    full_data.push_back(OPCODE_REQUEST);
    full_data.push_back(length);
    full_data.insert(full_data.end(), instruction_data.begin(), instruction_data.end());

    uint8_t checksum = calculateChecksum(full_data);
    full_data.push_back(checksum);

    return encryptData(full_data.data(), full_data.size());
}

// Sanitize MAC address for use as NVS key
String sanitizeKey(const String& mac) {
    String key = mac;
    key.replace(":", "");
    return key;
}

// Check if device was already scanned
bool isDeviceScanned(const String& macAddress) {
    String key = sanitizeKey(macAddress);
    preferences.begin("unitree_scan", true);
    bool exists = preferences.isKey(key.c_str());
    preferences.end();
    return exists;
}

// Save device data to NVS
void saveDeviceData(const DeviceData& data) {
    String key = sanitizeKey(data.macAddress);
    preferences.begin("unitree_scan", false);
    preferences.putString(key.c_str(), data.serialNumber);
    preferences.end();
    devicesScanned++;

    Serial.println("    Saved to NVS");

    // Update BLE characteristics for web dashboard
    if (pDeviceListChar && pDeviceCountChar) {
        String deviceList = getAllDevicesFromNVS();
        uint8_t count = getDeviceCountFromNVS();

        pDeviceListChar->setValue(deviceList.c_str());
        pDeviceListChar->notify();

        pDeviceCountChar->setValue(&count, 1);
        pDeviceCountChar->notify();
    }
}

// Get all devices directly from NVS as formatted string
String getAllDevicesFromNVS() {
    String result = "";

    nvs_handle_t handle;
    esp_err_t err = nvs_open("unitree_scan", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return result;
    }

    // Iterate through all entries in the namespace
    nvs_iterator_t it = NULL;
    err = nvs_entry_find("nvs", "unitree_scan", NVS_TYPE_STR, &it);

    while (err == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        // Read the value for this key
        size_t required_size = 0;
        err = nvs_get_str(handle, info.key, NULL, &required_size);
        if (err == ESP_OK && required_size > 0) {
            char* value = (char*)malloc(required_size);
            err = nvs_get_str(handle, info.key, value, &required_size);
            if (err == ESP_OK) {
                // Reconstruct MAC address from key (add colons back)
                String macKey = String(info.key);
                String macAddress = "";
                for (size_t i = 0; i < macKey.length(); i += 2) {
                    if (i > 0) macAddress += ":";
                    macAddress += macKey.substring(i, i + 2);
                }

                result += macAddress + "|" + String(value) + "\n";
            }
            free(value);
        }

        err = nvs_entry_next(&it);
    }

    nvs_release_iterator(it);
    nvs_close(handle);

    return result;
}

// Get device count directly from NVS
uint8_t getDeviceCountFromNVS() {
    uint8_t count = 0;

    nvs_handle_t handle;
    esp_err_t err = nvs_open("unitree_scan", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return 0;
    }

    // Count entries in the namespace
    nvs_iterator_t it = NULL;
    err = nvs_entry_find("nvs", "unitree_scan", NVS_TYPE_STR, &it);

    while (err == ESP_OK) {
        count++;
        err = nvs_entry_next(&it);
    }

    nvs_release_iterator(it);
    nvs_close(handle);

    return count;
}

// Notification callback
static void notifyCallback(BLERemoteCharacteristic* pChar, uint8_t* pData, size_t length, bool isNotify) {
    auto decrypted = decryptData(pData, length);

    if (decrypted.size() < 5 || decrypted[0] != OPCODE_RESPONSE) {
        return;
    }

    if (!validateChecksum(decrypted)) {
        return;
    }

    uint8_t instruction = decrypted[2];

    if (instruction == INSTR_GET_SERIAL) {
        uint8_t chunkIndex = decrypted[3];
        uint8_t totalChunks = decrypted[4];

        std::vector<uint8_t> chunkData(decrypted.begin() + 5, decrypted.end() - 1);
        serialChunks[chunkIndex] = chunkData;
        serialTotalChunks = totalChunks;

        if (serialChunks.size() >= totalChunks) {
            serialNumber = "";
            for (uint8_t i = 1; i <= totalChunks; i++) {
                if (serialChunks.find(i) != serialChunks.end()) {
                    for (uint8_t byte : serialChunks[i]) {
                        if (byte != 0x00) {
                            serialNumber += (char)byte;
                        }
                    }
                }
            }
            serialComplete = true;
        }
    }
}

// Connect and fetch serial
bool connectAndFetchSerial(BLEAddress address, String deviceName) {
    String macAddress = address.toString().c_str();

    Serial.printf("\n[*] %s (%s)\n", deviceName.c_str(), macAddress.c_str());

    // Check if already scanned
    if (isDeviceScanned(macAddress)) {
        Serial.println("    Already scanned - skipping");
        return false;
    }

    // Reset serial collector
    serialChunks.clear();
    serialTotalChunks = 0;
    serialComplete = false;
    serialNumber = "";

    // Create client if needed
    if (!pClient) {
        pClient = BLEDevice::createClient();
    }

    // Connect
    if (!pClient->connect(address)) {
        Serial.println("    Connection failed");
        return false;
    }

    // Get service and characteristics
    BLERemoteService* pService = pClient->getService(SERVICE_UUID);
    if (!pService) {
        pClient->disconnect();
        return false;
    }

    BLERemoteCharacteristic* pNotifyChar = pService->getCharacteristic(CHARACTERISTIC_NOTIFY);
    BLERemoteCharacteristic* pWriteChar = pService->getCharacteristic(CHARACTERISTIC_WRITE);

    if (!pNotifyChar || !pWriteChar) {
        pClient->disconnect();
        return false;
    }

    // Subscribe to notifications
    if (pNotifyChar->canNotify()) {
        pNotifyChar->registerForNotify(notifyCallback);
    }

    delay(100);

    // Send handshake
    std::vector<uint8_t> handshakeData = {0x00, 0x00};
    for (char c : String(HANDSHAKE_CONTENT)) {
        handshakeData.push_back((uint8_t)c);
    }
    auto handshakePacket = createPacket(INSTR_HANDSHAKE, handshakeData);
    pWriteChar->writeValue(handshakePacket.data(), handshakePacket.size(), true);
    delay(1000);

    // Request serial number
    std::vector<uint8_t> serialData = {0x00};
    auto serialPacket = createPacket(INSTR_GET_SERIAL, serialData);
    pWriteChar->writeValue(serialPacket.data(), serialPacket.size(), true);

    // Wait for serial chunks
    uint32_t waitStart = millis();
    while (!serialComplete && (millis() - waitStart < NOTIFICATION_TIMEOUT)) {
        delay(100);
    }

    if (!serialComplete) {
        Serial.println("    Failed to receive serial");
        pClient->disconnect();
        return false;
    }

    Serial.printf("    Serial: %s\n", serialNumber.c_str());

    // Save to NVS
    DeviceData deviceData;
    deviceData.macAddress = macAddress;
    deviceData.serialNumber = serialNumber;
    saveDeviceData(deviceData);

    // Disconnect
    pClient->disconnect();
    return true;
}

// Scan callback
class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        if (isConnecting) return;

        String deviceName = advertisedDevice.getName().c_str();
        if (deviceName.length() == 0) return;

        // Check if Unitree device
        bool isUnitree = deviceName.startsWith("G1_") ||
                        deviceName.startsWith("Go2_") ||
                        deviceName.startsWith("B2_") ||
                        deviceName.startsWith("H1_") ||
                        deviceName.startsWith("X1_");

        if (isUnitree) {
            pServerAddress = new BLEAddress(advertisedDevice.getAddress());
            doConnect = true;
            advertisedDevice.getScan()->stop();
        }
    }
};

void setup() {
    Serial.begin(115200);
    delay(2000);

    Serial.println("\n=== ESP32 Unitree Scanner ===");
    Serial.println("Scanning for Unitree devices...\n");

    // Initialize crypto
    initCrypto();

    // Initialize NVS
    preferences.begin("unitree_scan", false);
    preferences.end();

    // Initialize BLE
    BLEDevice::init("ESP32-Scanner");

    // Create BLE Server for web dashboard
    pDashboardServer = BLEDevice::createServer();
    BLEService* pDashboardService = pDashboardServer->createService(DASHBOARD_SERVICE_UUID);

    // Create device list characteristic (read + notify)
    pDeviceListChar = pDashboardService->createCharacteristic(
        DEVICE_LIST_CHAR_UUID,
        BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY
    );

    // Create device count characteristic (read + notify)
    pDeviceCountChar = pDashboardService->createCharacteristic(
        DEVICE_COUNT_CHAR_UUID,
        BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY
    );

    // Initialize characteristics with loaded data from NVS
    String deviceList = getAllDevicesFromNVS();
    uint8_t deviceCount = getDeviceCountFromNVS();
    pDeviceListChar->setValue(deviceList.c_str());
    pDeviceCountChar->setValue(&deviceCount, 1);
    Serial.printf("Initialized BLE characteristics with %d devices\n", deviceCount);

    // Start service
    pDashboardService->start();

    // Start advertising (for web dashboard connection)
    BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(DASHBOARD_SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    pAdvertising->start();

    Serial.println("Web dashboard BLE server started");

    // Start scanning for Unitree devices
    BLEScan* pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
    pBLEScan->start(0, false);  // Scan continuously
}

void loop() {
    if (doConnect) {
        doConnect = false;
        isConnecting = true;

        if (pServerAddress) {
            connectAndFetchSerial(*pServerAddress, "Unitree Device");
            delete pServerAddress;
            pServerAddress = nullptr;
        }

        isConnecting = false;

        // Restart scan
        delay(2000);
        BLEScan* pBLEScan = BLEDevice::getScan();
        pBLEScan->start(0, false);
    }

    delay(1000);
}
