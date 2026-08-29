# IEC 61850 Security Gateway

An embedded Intrusion Detection System (IDS) designed for digital substation networks using IEC 61850, IEC 62351, and IEEE 802.1Q.

The gateway passively inspects raw Ethernet frames in real time and validates network traffic against an authorized engineering baseline derived from the Substation Configuration Description (SCD/SCL) file.

> **Note**: This system operates exclusively as a **passive monitoring and intrusion detection system**. It sniffs network traffic, detects anomalies, logs alerts, and streams real-time notifications to operators. It does **not** block, filter, drop, or alter network traffic on the physical substation bus.

---

## Key Features

- **Real Time Packet Demultiplexing**: Classifies GOOSE, Sampled Values, and MMS traffic and routes frames to dedicated processing queues.
- **GOOSE Monitoring**: Validates ASN.1 BER structure, destination MAC, APPID, VLAN ID, priority, configuration revision (`confRev`), state/sequence numbers (`stNum`/`sqNum`), and heartbeat/burst timing.
- **Sampled Values (SV) Monitoring**: Inspects 9-2LE streams for destination MAC, APPID, VLAN, `svID`, `confRev`, `nofASDU`, sample rate (`smpRate`), duplicate sample counts, gaps, and unexpected rollbacks.
- **MMS SCADA Monitoring**: Validates IPv4/TCP endpoints against the SCD baseline, checks COTP T-Selectors, and detects unauthorized SCADA write requests.
- **Dynamic Configuration Reloading**: Web UI parses SCL XML client-side into JSON and uploads it to the gateway over HTTP. The gateway stores it on an SD card and hot-reloads the active baseline without rebooting.
- **Persistent SD Card Logging**: Records detected security alerts in JSON Lines format (`0:/alerts.json`) on MicroSD storage with monotonic alert ID tracking.
- **Real-Time Web Console**: Embedded HTTP server provides a browser dashboard with live Server-Sent Events (SSE) alert streaming, protocol filtering, and CSV export.
- **Multi-Protocol Simulator**: Python test suite with 25 pre-built test scenarios across GOOSE, SV, and MMS for reproducible validation.

---

## Supported Protocols

| Protocol           | Standard                 | Transport / EtherType             | Monitored Fields & Parameters                                                             |
| :----------------- | :----------------------- | :-------------------------------- | :---------------------------------------------------------------------------------------- |
| **GOOSE**          | IEC 61850-8-1            | `0x88B8` (Ethernet II / 802.1Q)   | MAC, APPID, VLAN, Priority, `confRev`, `stNum`, `sqNum`, `minTimeMs`, `timeAllowedToLive` |
| **Sampled Values** | IEC 61850-9-2LE          | `0x88BA` (Ethernet II / 802.1Q)   | MAC, APPID, VLAN, Priority, `svID`, `confRev`, `nofASDU`, `smpRate`, `smpCnt` sequence    |
| **MMS**            | IEC 61850-8-1 / ISO 9506 | TCP port 102 (TPKT / COTP / IPv4) | Source/Destination IP, Destination Port, COTP TSEL, MMS Write Requests                    |
| **VLAN & QoS**     | IEEE 802.1Q              | `0x8100`                          | 12-bit VLAN ID, 3-bit Priority Code Point (PCP)                                           |

---

## Documentation

Comprehensive project documentation is available in the `docs/` directory:

- [**System Architecture**](docs/architecture.md): FreeRTOS task design, memory pools, queues, packet demultiplexing, SCD configuration lifecycle, and API endpoints.
- [**Intrusion Detection Rules**](docs/detection-rules.md): Complete list of all GOOSE, SV, and MMS detection rules, trigger conditions, severities, and event schemas.
- [**Traffic Simulator & Test Suite**](docs/simulator.md): Simulator architecture, CLI options, parameter configuration, and catalog of all 25 test scenarios.
