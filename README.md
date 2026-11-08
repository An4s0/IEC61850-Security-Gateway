# IEC 61850 Security Gateway

An embedded, high-performance Intrusion Detection System (IDS) designed for digital substation networks utilizing **IEC 61850-8-1 (GOOSE, MMS)**, **IEC 61850-9-2LE (Sampled Values)**, **IEC 62351**, and **IEEE 802.1Q**.

The gateway passively inspects raw Ethernet frames in real time and validates network traffic against an authorized engineering baseline derived from the Substation Configuration Description (SCD/SCL) file.

> **Important**: This system operates exclusively as a **passive monitoring and intrusion detection system**. It sniffs network traffic, detects anomalies, logs alerts, and streams real-time notifications to operators. It does **not** block, filter, drop, or alter network traffic on the physical substation process and station buses.

---

## Key Features

- **Ethernet Frame Classification**: The driver passes received pbufs to the raw classifier. GOOSE and SV frames are copied into protocol pools and queued for inspection. MMS candidates are copied for inspection and continue through lwIP.
- **GOOSE Monitoring (IEC 61850-8-1)**: Validates ASN.1 BER structure, destination MAC, APPID, VLAN ID, priority code point (PCP), configuration revision (`confRev`), state/sequence numbers (`stNum`/`sqNum`), and heartbeat/burst timing against SCD parameters (`minTimeMs`/`maxTimeMs`).
- **Sampled Values (SV) Monitoring (IEC 61850-9-2LE)**: Inspects high-rate digital stream parameters including destination MAC, APPID, VLAN, `svID`, `confRev`, `nofASDU`, the optional `smpRate` field, consecutive duplicate sample counts (`smpCnt`), sequence gaps, and unexpected rollbacks.
- **MMS SCADA Monitoring (IEC 61850-8-1 / ISO 9506)**: Inspects IPv4/TCP endpoints and COTP selectors. A payload scan identifies byte patterns treated as MMS write requests. The detector does not reassemble the TCP stream.
- **RAM Alert Logging**: Protocol tasks submit normal and anomalous events to 32 independent RAM slots. A background task writes records to SD. Slot contention, buffer capacity, and storage errors can prevent records from being saved.
- **High-Throughput Native SDMMC Storage**: Uses a native 4-bit SDMMC1 driver on STM32F7 (PC8–PC11 data, PC12 CK, PD2 CMD, PG2 Card Detect) replacing legacy SPI. Persists alerts in Newline Delimited JSON format (`0:/alerts/alerts.ndjson`) with automatic migration from legacy `0:/alerts.json`.
- **Fast-Boot Binary SCD Caching**: Caches validated SCD baseline configurations in packed binary format (`0:/config/ids_config.bin`) with IEEE 802.3 CRC32 verification, allowing startup to load the binary without parsing JSON when the cache is valid.
- **Dynamic SCD Hot-Reloading**: Web UI parses SCL XML client-side into JSON and sends it in an HTTP upload to the gateway. The system compiles the baseline to binary and swaps active pointers under a FreeRTOS mutex without requiring a reboot.
- **Runtime System Tuning (`system_config`)**: Dynamically configures detection thresholds, feature toggles (timing checks, state checks, smpCnt checks), fallback intervals, and logging parameters over the HTTP API (`/api/config`) with persistent binary storage (`0:/config/system_config.bin`).
- **System Event Logging**: Integrated multi-level system logger (`0:/logs/system.log`) with non-blocking ring buffer queue and automatic file rotation (up to 3 × 64 KB).
- **Packet Accounting**: Per-protocol counters report frames delivered by the RX driver, parser outcomes, and inspection enqueue failures. The dashboard polls `/api/accounting` for counters and alert-storage health.
- **Dual Web Architecture & Real-Time Console**: Embedded LwIP HTTP server on port 80 serves a modern responsive dashboard (`iec61850-security-gateway.html`), while a dedicated HTTP API on port 8080 provides REST endpoints and live Server-Sent Events (SSE) streaming for real-time alert monitoring, protocol filtering, and CSV export.
- **Unified Multi-Protocol Simulator**: Python test suite with 25 pre-built test scenarios across GOOSE (8), SV (11), and MMS (6) supporting reproducible pseudo-random execution seeds.

---

## Supported Protocols & Standards

| Protocol | Standard | Transport / EtherType | Monitored Fields & Parameters | Default Severity |
| :--- | :--- | :--- | :--- | :--- |
| **GOOSE** | IEC 61850-8-1 | `0x88B8` (Ethernet II / 802.1Q) | MAC, APPID, VLAN ID, Priority, `confRev`, `stNum`, `sqNum`, `minTimeMs`, `timeAllowedToLive` | `HIGH` / `WARNING` |
| **Sampled Values** | IEC 61850-9-2LE | `0x88BA` (Ethernet II / 802.1Q) | MAC, APPID, VLAN ID, Priority, `svID`, `confRev`, `nofASDU`, `smpRate`, `smpCnt` sequence | `HIGH` / `WARNING` |
| **MMS** | IEC 61850-8-1 / ISO 9506 | TCP port 102 (TPKT / COTP / IPv4) | Source/Destination IP, Destination Port, COTP TSEL, MMS Write Requests | `CRITICAL` / `HIGH` / `WARNING` |
| **VLAN & QoS** | IEEE 802.1Q | `0x8100` | 12-bit VLAN ID, 3-bit Priority Code Point (PCP) | `HIGH` / `WARNING` |

---

## Hardware & Firmware Specifications

- **Microcontroller**: STM32F767ZI (ARM Cortex-M7 with FPU, 216 MHz CPU with Over-Drive, 2 MB Flash, 512 KB SRAM, L1 Instruction & Data Caches).
- **Network Interface**: Microchip LAN8742A RMII 10/100 Ethernet PHY with auto-negotiation and hardware checksum offload.
- **Storage Peripheral**: Native SDMMC1 hardware controller operating over a 4-bit bus with DMA and active-low card detection (`PG2`).
- **RTOS & Stacks**: FreeRTOS CMSIS-RTOS v1, LwIP 2.1.2 TCP/IP stack, FatFs R0.12c filesystem.

---

## MicroSD Card Storage Layout

```text
0:/
├── alerts/
│   └── alerts.ndjson          # Persisted security alerts in Newline Delimited JSON
├── config/
│   ├── ids_config.bin         # Compiled binary SCD baseline cache (IDSC format, CRC32)
│   ├── ids_config.bak         # Backup baseline binary during reloads
│   └── system_config.bin      # Binary runtime IDS settings and thresholds
├── logs/
│   ├── system.log             # Active system diagnostic log
│   ├── system.log.1           # First rotated log file (64 KB max)
│   └── system.log.2           # Second rotated log file (64 KB max)
└── substation/
    └── substation.json        # Raw SCD JSON uploaded from Web Console
```

---

## Project Structure

```text
IEC61850 Security Gateway/
├── docs/                      # Comprehensive technical documentation
│   ├── architecture.md        # System architecture, FreeRTOS tasks, and memory layout
│   ├── detection-rules.md     # IDS rules, anomaly triggers, and event schemas
│   └── simulator.md           # Traffic simulator architecture and scenario catalog
├── firmware/
│   └── IEC61850_Security_Gateway_v0.1/
│       ├── Core/              # Core application logic, IDS engines, and drivers
│       │   ├── Inc/           # Public headers (goose.h, sv.h, mms.h, security.h, etc.)
│       │   └── Src/           # Source files (goose.c, sv.c, mms.c, http_api.c, sdmmc.c, etc.)
│       ├── LWIP/              # LwIP target configuration and Ethernet interface
│       ├── FATFS/             # FatFs file system bindings for SDMMC
│       ├── Middlewares/       # FreeRTOS, LwIP, and FatFs middleware
│       ├── iec61850-security-gateway.html # Single-page web console dashboard
│       └── CMakeLists.txt     # CMake build configuration
├── hardware/
│   └── IEC61850_Security_Gateway_v0.2/ # KiCad hardware schematics and PCB layout
├── simulator/                 # Python multi-protocol test suite
│   ├── goose/                 # GOOSE generator and 8 attack scenarios
│   ├── sv/                    # Sampled Values generator and 11 attack scenarios
│   ├── mms/                   # MMS client/server and 6 attack scenarios
│   ├── substation.scd         # Reference engineering substation configuration
│   └── run_all.py             # Unified scenario runner with randomized execution
└── README.md                  # Project overview and quick reference
```

---

## Documentation

Detailed technical documentation is available in the [`docs/`](docs/) directory:

- [**System Architecture**](docs/architecture.md): FreeRTOS task prioritization, queues, packet classification and accounting, native SDMMC1 driver, SCD binary cache lifecycle, and REST/SSE API endpoints.
- [**Intrusion Detection Rules**](docs/detection-rules.md): Complete catalog of GOOSE, SV, and MMS detection rules, trigger conditions, severities, alert handling, and NDJSON event schemas.
- [**Traffic Simulator & Test Suite**](docs/simulator.md): Simulator architecture, CLI options, parameter configuration, and catalog of all 25 test scenarios.
