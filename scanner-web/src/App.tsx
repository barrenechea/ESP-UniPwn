import { useEffect, useState, type ReactElement } from 'react'
import './App.css'

type ScannedDevice = {
  mac: string
  serial: string
}

const SCANNER_SERVICE_UUID = '0000fff0-0000-1000-8000-00805f9b34fb'
const DEVICE_LIST_CHAR_UUID = '0000fff1-0000-1000-8000-00805f9b34fb'
const DEVICE_COUNT_CHAR_UUID = '0000fff2-0000-1000-8000-00805f9b34fb'

const parseDeviceList = (value: DataView): ScannedDevice[] => {
  const decoder = new TextDecoder()
  const listText = decoder.decode(value)

  return listText
    .split('\n')
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => {
      const [mac = '', serial = ''] = line.split('|')
      return { mac, serial }
    })
}

function App(): ReactElement {
  const [isConnected, setIsConnected] = useState(false)
  const [devices, setDevices] = useState<ScannedDevice[]>([])
  const [status, setStatus] = useState('Idle - Scanner Disconnected')
  const [bleDevice, setBleDevice] = useState<BluetoothDevice | null>(null)
  const [isBleSupported, setIsBleSupported] = useState(true)

  useEffect(() => {
    const supportsBluetooth =
      typeof navigator !== 'undefined' &&
      !!navigator.bluetooth &&
      typeof navigator.bluetooth.requestDevice === 'function'

    if (!supportsBluetooth) {
      setIsBleSupported(false)
      setStatus('Web Bluetooth unsupported. Use Chrome or Edge on desktop over HTTPS.')
    }
  }, [])

  const connectToScanner = async (): Promise<void> => {
    if (
      typeof navigator === 'undefined' ||
      !navigator.bluetooth ||
      typeof navigator.bluetooth.requestDevice !== 'function'
    ) {
      setStatus('Error: Web Bluetooth unavailable in this browser.')
      return
    }

    try {
      setStatus('Requesting ESP-UniPwn scanner...')

      const device = await navigator.bluetooth.requestDevice({
        filters: [{ services: [SCANNER_SERVICE_UUID] }]
      })

      setStatus('Establishing BLE session...')

      const gatt = device.gatt
      if (!gatt) {
        throw new Error('GATT server not available on the selected device.')
      }

      const server = await gatt.connect()
      const service = await server.getPrimaryService(SCANNER_SERVICE_UUID)

      const countChar = await service.getCharacteristic(DEVICE_COUNT_CHAR_UUID)
      const countValue = await countChar.readValue()
      const deviceCount = countValue.getUint8(0)
      setStatus(`Scanner reports ${deviceCount} Unitree targets`)

      const listChar = await service.getCharacteristic(DEVICE_LIST_CHAR_UUID)
      const listValue = await listChar.readValue()
      const parsedDevices = parseDeviceList(listValue)

      setDevices(parsedDevices)
      setIsConnected(true)
      setBleDevice(device)
      setStatus(`Connected • ${deviceCount} Unitree devices`)

    } catch (error) {
      console.error('Bluetooth error:', error)
      const message = error instanceof Error ? error.message : 'Unknown error'
      setStatus(`Error: ${message}`)
      setIsConnected(false)
    }
  }

  const disconnect = (): void => {
    if (bleDevice) {
      const gatt = bleDevice.gatt
      if (gatt?.connected) {
        gatt.disconnect()
      }
    }

    setIsConnected(false)
    setBleDevice(null)
    setDevices([])
    setStatus('Idle - Scanner Disconnected')
  }

  const refresh = async (): Promise<void> => {
    if (!bleDevice) {
      return
    }

    const gatt = bleDevice.gatt
    if (!gatt?.connected) {
      return
    }

    try {
      setStatus('Syncing latest telemetry...')

      const service = await gatt.getPrimaryService(SCANNER_SERVICE_UUID)
      const countChar = await service.getCharacteristic(DEVICE_COUNT_CHAR_UUID)
      const countValue = await countChar.readValue()
      const deviceCount = countValue.getUint8(0)

      const listChar = await service.getCharacteristic(DEVICE_LIST_CHAR_UUID)
      const listValue = await listChar.readValue()
      const parsedDevices = parseDeviceList(listValue)

      setDevices(parsedDevices)
      setStatus(`Connected • ${deviceCount} Unitree devices`)
    } catch (error) {
      console.error('Refresh error:', error)
      const message = error instanceof Error ? error.message : 'Unknown error'
      setStatus(`Sync error: ${message}`)
    }
  }

  return (
    <div className="app">
      <div className="layout">
        <header className="top-bar">
          <div className="top-copy">
            <h1>ESP-UniPwn Scanner</h1>
            <p>Web BLE console for Unitree reconnaissance</p>
          </div>
          <div className="status-chip" role="status">
            <span
              className={`status-indicator ${isConnected ? 'online' : 'offline'}`}
              aria-hidden="true"
            />
            <span className="status-text">{status}</span>
          </div>
        </header>

        <main className="content">
          <section className="panel control-panel">
            <div className="panel-header">
              <h2>Scanner Session</h2>
              <p>
                {isConnected
                  ? 'Keep the BLE link alive to maintain a live feed of Unitree telemetry.'
                  : 'Link your ESP32 scanner to enumerate nearby Unitree robots.'}
              </p>
            </div>
            <div className="panel-actions">
              {!isConnected ? (
                <button
                  onClick={connectToScanner}
                  className="btn primary"
                  disabled={!isBleSupported}
                >
                  Link Scanner
                </button>
              ) : (
                <>
                  <button onClick={refresh} className="btn subtle">
                    Sync Devices
                  </button>
                  <button onClick={disconnect} className="btn danger">
                    Terminate Link
                  </button>
                </>
              )}
            </div>
          </section>

          {!isBleSupported && (
            <section className="panel support-panel">
              <div className="panel-header">
                <h2>Browser not supported</h2>
                <p>
                  Your browser cannot access the Web Bluetooth API. Use Chrome or Edge on desktop and
                  ensure ESP-UniPwn is served over HTTPS.
                </p>
              </div>
            </section>
          )}

          <section className="panel devices-panel">
            <div className="panel-header devices-header">
              <div>
                <h2>Unitree Device Archive</h2>
                <p>
                  {isConnected
                    ? 'Current and historical data as reported by the ESP-UniPwn scanner.'
                    : 'Connect the scanner to populate the Unitree device log.'}
                </p>
              </div>
              <span className="count-badge" aria-label={`${devices.length} Unitree devices recorded`}>
                {devices.length}
              </span>
            </div>

            {!isConnected ? (
              <div className="empty-state">
                <p>Scanner idle.</p>
                <p>Link the ESP32 node to review harvested Unitree data.</p>
              </div>
            ) : devices.length === 0 ? (
              <div className="empty-state">
                <p>No Unitree devices recorded yet.</p>
                <p>The scanner will add entries as soon as new targets broadcast.</p>
              </div>
            ) : (
              <ol className="devices-list">
                {devices.map((device, index) => (
                  <li key={`${device.mac}-${index}`} className="device-row">
                    <span className="device-number" aria-hidden="true">
                      {index + 1}
                    </span>
                    <div className="device-meta">
                      <span className="label">MAC</span>
                      <span className="value">{device.mac}</span>
                    </div>
                    <div className="device-meta">
                      <span className="label">Serial Number</span>
                      <span className="value accent">{device.serial}</span>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </section>
        </main>

        <footer className="footer">
          <span>ESP-UniPwn tooling for Unitree research</span>
        </footer>
      </div>
    </div>
  )
}

export default App
