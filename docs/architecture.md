# System Architecture

This document details the software and hardware architecture of the **IEC 61850 Security Gateway**, an embedded Intrusion Detection System (IDS) for digital substation networks.

---

## 1. System Overview & Hardware Platform

The gateway is a passive, high-throughput network monitoring appliance built on the **STM32F767ZI** microcontroller (ARM Cortex-M7 with double-precision FPU).

```
                      +-------------------------------------------------+
                      |            Substation Network Bus               |
                      |        (Process Bus & Station Bus)              |
                      +-------------------------------------------------+
                                               |
                                     (Passive Ethernet Tap)
                                               v
+---------------------------------------------------------------------------------------+
|  STM32F767ZI Gateway Hardware Platform (216 MHz Cortex-M7)                            |
|                                                                                       |
|  +--------------------+     +---------------------+     +--------------------------+  |
|  | LAN8742A RMII PHY  | --> | STM32 ETH MAC + DMA | --> | Raw Packet Demux         |  |
|  +--------------------+     +---------------------+     +--------------------------+  |
|                                                                      |                |
|                      +------------------------+----------------------+                |
|                      |                        |                      |                |
|                      v                        v                      v                |
|               [ GOOSE Queue ]          [ SV Queue ]            [ MMS Queue ]          |
|                      |                        |                      |                |
|                      v                        v                      v                |
|               +--------------+         +--------------+        +--------------+       |
|               |  GooseTask   |         |    SVTask    |        |   MMSTask    |       |
|               |  (Priority   |         |  (Priority   |        |  (Priority   |       |
|               |    High)     |         |    High)     |        |    High)     |       |
|               +--------------+         +--------------+        +--------------+       |
|                      |                        |                      |                |
|                      +-------------------+----+----------------------+                |
|                                          |                                            |
|                                          v                                            |
|                        +-----------------------------------+                          |
|                        | Independent RAM Alert Slots        |                          |
|                        | (32 slots; no aggregation)         |                          |
|                        +-----------------------------------+                          |
|                                          |                                            |
|                         (Periodic Flush in defaultTask)                               |
|                                          |                                            |
|                      +-------------------+--------------------+                       |
|                      |                                        |                       |
|                      v                                        v                       |
|         +---------------------------+            +---------------------------+        |
|         | Native 4-bit SDMMC1 FatFs |            | Dual HTTP Server Engine   |        |
|         | 0:/alerts/alerts.ndjson   |            | - Port 80: Web Dashboard  |        |
|         | 0:/config/ids_config.bin  |            | - Port 8080: REST & SSE   |        |
|         | 0:/logs/system.log        |            +---------------------------+        |
|         +---------------------------+                                                 |
+---------------------------------------------------------------------------------------+
```

### Hardware Specifications

* **Microcontroller**: STMicroelectronics STM32F767ZIT6 (ARM Cortex-M7 running at 216 MHz via PLL with Over-Drive enabled, 2 MB Flash, 512 KB SRAM).
* **Instruction & Data Caches**: The startup code enables the instruction cache. The Ethernet RX callback also contains data-cache invalidation code.
* **Ethernet Subsystem**: Microchip LAN8742A 10/100 Mbps Ethernet PHY connected via Reduced Media Independent Interface (RMII) using dedicated DMA descriptors with hardware checksum offloading.
* **Storage Controller**: Native SDMMC1 hardware peripheral configured for high-speed 4-bit bus mode (PC8–PC11: D0–D3, PC12: CK, PD2: CMD, PG2: Card Detect with internal pull-up).

---

## 2. MicroSD Storage Architecture

The gateway uses the FatFs file system over native SDMMC1 hardware. The SD card structure is organized as follows:

| Directory / File | Format | Description |
| :--- | :--- | :--- |
| `0:/alerts/alerts.ndjson` | NDJSON | Persisted intrusion alerts stored in Newline Delimited JSON. Auto-migrates from legacy `0:/alerts.json`. |
| `0:/config/ids_config.bin` | Binary | Packed binary cache of validated SCD baseline with IEEE 802.3 CRC32 checksum. |
| `0:/config/ids_config.bak` | Binary | Backup binary baseline file used during atomic configuration reloading. |
| `0:/config/system_config.bin` | Binary | Persisted runtime system configuration and threshold tuning parameters. |
| `0:/substation/substation.json` | JSON | Raw substation configuration JSON uploaded from the Web Console. |
| `0:/logs/system.log` | Text | Active rotating system diagnostics log (64 KB maximum size). |
| `0:/logs/system.log.1` / `.2` | Text | First and second rotated historical diagnostic logs. |

---

## 3. Packet Demultiplexing & Accounting

Ethernet frames are captured at the lowest driver level in `ethernetif.c`. `ethernetif_input` calls `RawEth_Input` before passing a pbuf to lwIP. `RawEth_Input` calls `RawEth_Process` in `raw_eth.c`:

```
                       Incoming Ethernet Frame (DMA)
                                     |
                                     v
                           [ RawEth_Process() ]
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v (0x88B8 / 802.1Q)         v (0x88BA / 802.1Q)         v (0x0800 / 802.1Q)
     [ GOOSE ]                     [ SV ]                      [ IPv4 ]
         |                           |                           |
   Goose_Enqueue()              Sv_Enqueue()             is_mms_packet(Port 102)?
         |                           |                      /        \
         |                           |                 Yes /          \ No
         v                           v                    v            \
  (Returns true:              (Returns true:        Mms_Enqueue()       v
   eats frame,                 eats frame,                |       (Returns false:
   bypasses lwIP)              bypasses lwIP)             |        passes frame
                                                          v        to lwIP stack)
                                                   (Returns false:
                                                    continues to
                                                    lwIP stack)
```

1. **GOOSE (`0x88B8`)**: The driver copies the frame into `GoosePool` (16 × 512 bytes) and submits it to `GooseQueue`. `RawEth_Process` returns `true`, so that lwIP does not process the frame.
2. **Sampled Values (`0x88BA`)**: The driver copies the frame into `SvPool` (32 × 512 bytes) and submits it to `SVQueue`. `RawEth_Process` returns `true`, bypassing lwIP.
3. **802.1Q VLAN Tags (`0x8100`)**: The classifier reads the encapsulated EtherType. The protocol parsers read the VLAN ID and Priority Code Point (PCP). GOOSE and SV frames bypass lwIP.
4. **MMS Traffic (IPv4 `0x0800` on TCP Port 102)**: The IP header and TCP destination/source ports are inspected. If matching the configured MMS port (default 102), a copy is submitted to `MMSQueue` for IDS inspection, but `RawEth_Process` returns `false` so the packet continues through lwIP to maintain connection state.
5. **Other Traffic (ARP, ICMP, HTTP API)**: Continues normally through lwIP.

The Ethernet driver uses custom pbufs backed by the RX pool. The receive task frees the original pbuf after GOOSE or SV classification. For other traffic, lwIP owns it after a successful input call. An input error causes the receive task to free it. IDS inspection uses a separate copy for each queued protocol frame. Pool exhaustion, an oversized frame, an incomplete copy, or a full protocol queue can prevent inspection. These failures do not represent enforcement on the monitored bus.

### Packet Accounting

`GET /api/accounting` returns cumulative 32-bit counters since boot. The `protocols` array order is GOOSE, SV, MMS, and Other. Updates and snapshots use critical sections. Counters saturate at `UINT32_MAX`; `saturated` reports an attempted increment beyond that value.

| Field | Counting point |
| :--- | :--- |
| `rx` | `RawEth_Process` classifies a pbuf returned by the Ethernet driver. |
| `parsed` | A supported protocol parser returns success. |
| `parse_failed` | A supported protocol parser returns failure. |
| `drop_size_or_init` | An inspection frame is too large, its pool is unavailable, or the pbuf copy is incomplete. |
| `drop_pool` | The protocol frame pool cannot allocate a buffer. |
| `drop_queue` | The protocol queue rejects the frame. |

For each supported protocol, `rx` includes frames still in flight as well as completed parser and enqueue outcomes. Before saturation, the difference between RX and the sum of parsed, parse-failed, and inspection-drop counts includes in-flight work and any unaccounted paths. Other traffic is classified but does not enter these protocol parsers. `rx` does not include frames lost before a pbuf is returned, such as some DMA or RX-buffer failures. MMS classification follows the configured TCP port and inspection setting; it does not prove that a frame contains a complete MMS message.

`last_parsed_ms` is the gateway tick at the last successful protocol parse. The same response includes RAM alerts created, alerts synced during the current boot, alert-slot failures, storage errors, and slot usage. These measurements are distinct from the total historical records in the alerts API.

---

## 4. FreeRTOS Tasks & Memory Allocation

The firmware utilizes CMSIS-RTOS v1 (FreeRTOS 10.x) to isolate real-time network analysis from low-priority storage and web operations:

| Task Name | Function | Priority | Stack Size | Queue / Buffer | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GooseTask` | `StartGooseTask` | `osPriorityHigh` | 1024 words (4 KB) | `GooseQueue` (16 frames)<br>`GoosePool` (16 × 512 B) | Real-time ASN.1 BER decoding, baseline validation, state/sequence checks, timing verification. |
| `SVTask` | `StartSVTask` | `osPriorityHigh` | 2048 words (8 KB) | `SVQueue` (32 frames)<br>`SvPool` (32 × 512 B) | High-rate 9-2LE stream validation, `smpCnt` gap/duplicate/rollback detection, `smpRate` field comparison. |
| `MMSTask` | `StartMMSTask` | `osPriorityHigh` | 2048 words (8 KB) | `MMSQueue` (16 frames)<br>`MmsPool` (16 × 512 B) | IPv4 endpoint validation, COTP TSEL checking, unauthorized SCADA write command detection. |
| `SCD_StorageTask` | `StartSCD_StorageTask` | `osPriorityAboveNormal` | 1024 words (4 KB) | `SCD_StorageQueue` (8 chunks)<br>`SCDChunkPool` (6 × 1024 B) | Asynchronous SD card streaming writes during client SCL JSON uploads. |
| `SCD_ConfigTask` | `StartSCD_ConfigTask` | `osPriorityNormal` | 2048 words (8 KB) | `SCD_ConfigQueue` (4 messages) | JSON parsing, baseline compilation into packed binary `ids_config.bin`, CRC32 verification, mutexed baseline hot-swap. |
| `defaultTask` | `StartDefaultTask` | `osPriorityNormal` | 1024 words (4 KB) | None | System initialization, LwIP startup, HTTP servers initialization, 100 ms periodic flush for alerts and logs. |
| `tcpip_thread` | LwIP Core | `osPriorityAboveNormal` | `TCPIP_THREAD_STACKSIZE` = 2048 | LwIP mbox | Handles lwIP networking and HTTP services. The separate MMS IDS parser receives raw frames. |

---

## 5. SCD Baseline Lifecycle & Binary Caching

The gateway compares selected protocol fields with the active Substation Configuration Description (SCD/SCL):

```
+------------------------------------------------------------------------------------+
|                               Web Browser Dashboard                                |
|  User drops substation.scd (XML) -> Client-side XML-to-JSON Parser -> Clean JSON   |
+------------------------------------------------------------------------------------+
                                         |
                                         v HTTP POST /api/scd (request body)
+------------------------------------------------------------------------------------+
|  SCD_StorageTask: Receives 1024-byte chunks -> Writes 0:/substation/substation.json|
+------------------------------------------------------------------------------------+
                                         |
                                         v Signals SCD_ConfigTask
+------------------------------------------------------------------------------------+
|  SCD_ConfigTask: Validates records -> Compiles packed binary header & structs      |
|  -> Calculates IEEE 802.3 CRC32 -> Writes 0:/config/ids_config.bin                |
|  -> Calls SCD_Config_Lock() -> Swaps active baseline pointers -> Unlock            |
+------------------------------------------------------------------------------------+
```

### Fast-Boot Binary Cache (`ids_config.bin`)

To ensure rapid recovery after substation power cycles, the gateway uses a custom binary format (`IDSC`):
* **Magic Number**: `0x49445343` ("IDSC")
* **Format Version**: 1
* **Header Structure (`ids_bin_header_t`)**: 128 bytes packed header containing CRC32, timestamp, substation name, and counts for IEDs (max 256), GOOSE streams (max 128), SV streams (max 64), and MMS servers (max 256).
* **Startup Sequence**: On boot, `SCD_Config_RequestLoadStartup()` checks `0:/config/ids_config.bin`. If the file exists and its CRC32 matches the payload, the entire baseline is loaded directly into RAM without JSON parsing when the cache is valid.

---

## 6. Non-Blocking Alert Logging & Streaming Engine

Protocol tasks call `Security_LogAlertToSD` for normal and anomalous events. Each accepted call occupies one of 32 independent RAM slots. The logger does not merge matching events. The call does not perform FatFs operations, but slot contention or a full buffer can reject an event.

The default task calls `Security_PeriodicFlush` after a 100 ms delay. It opens the alert file, writes a JSON line for each selected slot, and calls `f_sync` for each record. The persisted count increments only after a successful write and sync. An open error leaves pending slots in RAM. A write or sync error increments the storage-error counter; the selected slot is no longer queued. With SD logging disabled, records are not counted as persisted and are not broadcast by this path.

After a successful write and sync, the code submits the JSON line for SSE broadcast. SSE delivery is best effort: the message pool, callback, or client write can fail. It is not a receipt acknowledgement. The startup scan uses the maximum ID in the log to initialize the sequence. Clearing the log keeps the current sequence during that boot, but a later restart after a clear can reuse IDs.

RAM slots, SD writes, and SSE resources are finite. The implementation does not guarantee one saved record per received frame. Throughput and loss rates require measurement on the target hardware.

---

## 7. Runtime System Configuration (`system_config`)

System parameters can be dynamically tuned at runtime without recompiling firmware or rebooting:

```c
typedef struct {
    GooseConfig_t goose;     /* Timing/state checks enable, fallback min/max time, TTL multiplier */
    SvConfig_t sv;           /* smpCnt checks enable, fallback sample rate, idle timeout, wrap tolerance */
    MmsConfig_t mms;         /* Inspection enable, baseline checks enable, target TCP port */
    AlertsConfig_t alerts;   /* Legacy aggregation fields, print interval, SD logging enable */
    GatewaySystemConfig_t system; /* Gateway identifier string */
} SystemConfig_t;
```

* **Persistence**: Saved as packed binary `0:/config/system_config.bin` (with fallback migration from legacy `0:/system_config.json`).
* **API Access**: Managed via HTTP `GET /api/config`, `POST /api/config`, and `POST /api/config/reset`.
* **Legacy Alert Fields**: The configuration still contains aggregation and normal-traffic interval fields. The current alert-slot and normal-event paths do not use them.

---

## 8. Embedded Web Server & HTTP API Reference

The gateway runs two network services concurrently:
1. **LwIP HTTP Server (Port 80)**: Serves static web assets (`iec61850-security-gateway.html` pre-compiled in `fsdata.c`).
2. **Custom Non-Blocking HTTP API (Port 8080)**: Manages REST interactions, configuration uploads, and live SSE event streams.

### API Endpoints

| Method | Endpoint | Description | Request / Response Format |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/scd` | Retrieves summary of the active SCD baseline. | Returns `fileName`, `id`, and `version` for the active configuration. |
| `POST` | `/api/scd` | Streams a new SCD JSON configuration to the gateway. | Content-Type: `application/json`. Uploaded in chunks; triggers validation and hot reload. |
| `GET` | `/api/accounting` | Returns per-protocol packet counters and alert health. | JSON object with `protocols` and health fields; counters are since boot. |
| `GET` | `/api/alerts/events`<br>`/api/alerts/stream` | Server-Sent Events (SSE) stream for real-time alert notifications. | `Content-Type: text/event-stream`. Up to 4 simultaneous SSE clients supported. |
| `GET` | `/api/alerts`<br>`/api/alerts/history` | Retrieves historical alerts from `0:/alerts/alerts.ndjson`. | Returns an object with totals, `alerts`, and `count`. Optional `offset` and `limit` select records; limit defaults to 40 and is capped at 40. |
| `DELETE` | `/api/alerts` | Clears stored alert history from SD card; pending RAM slots remain. | Returns `{"status":"cleared"}`. |
| `POST` | `/api/alerts/clear` | Clears stored alert history from SD card; pending RAM slots remain. | Returns `{"status":"cleared"}`. |
| `GET` | `/api/config` | Retrieves the current runtime system configuration. | Returns JSON representation of `SystemConfig_t`. |
| `POST` | `/api/config` | Updates runtime system settings and writes to SD card. | Payload: JSON object with modified fields. |
| `POST` | `/api/config/reset` | Resets system configuration to factory defaults. | Returns updated default JSON configuration. |
| `OPTIONS` | `*` | Handles CORS preflight requests for all endpoints. | Returns standard CORS headers (`Access-Control-Allow-Origin: *`). |

### Dashboard and Retrieval Limits

The Packet Accounting section polls `/api/accounting` every five seconds. It shows protocol totals, inspection drops, RAM records, synced records, queue usage, storage errors, and the last parse tick. The alert view requests a snapshot of the history in batches, then filters and exports the loaded records in the browser. New alerts arrive through SSE when delivery succeeds. Refresh, concurrent history changes, storage failures, or missed SSE messages can affect the view. The code does not provide an end-to-end delivery acknowledgement.
