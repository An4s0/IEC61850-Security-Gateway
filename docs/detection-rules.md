# Intrusion Detection Rules

This document describes the detection paths implemented by the **IEC 61850 Security Gateway** Intrusion Detection System for **GOOSE (IEC 61850-8-1)**, **Sampled Values (IEC 61850-9-2LE)**, and **MMS (IEC 61850-8-1 / ISO 9506)** substation traffic.

> **Operational Principle:** The gateway operates strictly as a **passive intrusion detection system**. It does **not** block, drop, filter, or alter network traffic on physical substation buses. Protocol tasks submit events to RAM slots for SD storage. Queue contention, storage errors, or SSE delivery failures can prevent an event from reaching the dashboard.

---

## 1. Severity Taxonomy

The security engine categorizes events into four discrete severity levels:

| Severity | Color Code | Description | Typical Triggers |
| :--- | :--- | :--- | :--- |
| `CRITICAL` | Dark Red (`#991b1b`) | Imminent operational threat or unauthorized substation control attempt. | A payload pattern identified by the MMS detector as a write request. |
| `HIGH` | Red (`#d32f2f`) | Security policy violations, unrecognized devices, revision mismatches, or replay attacks. | Malformed APDUs, unknown control blocks, MAC/APPID/VLAN spoofing, sequence rollbacks. |
| `WARNING` | Amber (`#c8862a`) | Operational anomalies, network degradation, timing jitter, or non-fatal configuration drift. | Timing jitter (`TIMING_FAST`/`TIMING_SLOW`), `smpCnt` gaps/duplicates, TSEL mismatches. |
| `INFO` | Blue (`#2563eb`) | Normal baseline traffic telemetry and diagnostic operational events. | Normal protocol traffic events. System startup and configuration events use the separate system log. |

---

## 2. GOOSE Detection Rules

Implemented in [`Core/Src/goose.c`](../firmware/IEC61850_Security_Gateway_v0.1/Core/Src/goose.c).

| Event Type | Default Severity | Detection Condition | Security & Operational Impact |
| :--- | :--- | :--- | :--- |
| `GOOSE_MALFORMED_FRAME` | `HIGH` | Frame length is less than minimum (14 bytes), invalid ASN.1 BER tag/length fields, corrupted PDU header, or truncated payload. | Indicates packet corruption, protocol fuzzing, or malformed frame injection. |
| `GOOSE_UNKNOWN_CONTROL_BLOCK` | `HIGH` | Control block reference (`gocbRef`), `goID`, APPID, or destination MAC address is not found in the active SCD baseline. | Rogue IED injection, unauthorized publisher, or obsolete device transmitting on the bus. |
| `GOOSE_MAC_MISMATCH` | `HIGH` | Destination multicast MAC address does not match the expected SCD baseline address for the given stream. | Misconfigured network routing, MAC spoofing, or stream hijacking. |
| `GOOSE_APPID_MISMATCH` | `HIGH` | The 16-bit APPID does not match the value defined in the active SCD baseline. | Packet injection, stream masquerading, or publisher configuration mismatch. |
| `GOOSE_VLAN_MISMATCH` | `HIGH` | 802.1Q VLAN tag is absent when expected, present when unexpected, or the 12-bit VLAN ID differs from baseline. | VLAN hopping, switch trunking misconfiguration, or unauthorized cross-VLAN bridging. |
| `GOOSE_VLAN_PRIORITY_MISMATCH` | `WARNING` | VLAN Priority Code Point (PCP) differs from the SCD baseline priority (typically 4 for GOOSE). | QoS degradation; may cause critical trip commands to experience queuing delays in switches. |
| `GOOSE_CONFREV_MISMATCH` | `HIGH` | Configuration revision (`confRev`) in the frame differs from the active SCD baseline value. | Stale baseline configuration or uncoordinated firmware/SCL change on an IED. |
| `GOOSE_STATE_ANOMALY` | `HIGH` / `WARNING` | Unexpected `stNum` rollback, or duplicate/rollback `sqNum` while `stNum` is unchanged. An expired stream with `sqNum == 0` can be treated as a restart. | High severity indicates replay attacks or injection of stale trip messages. Warning indicates packet reordering. |
| `GOOSE_TIMING_FAST` | `WARNING` | For an eligible sequence advance with unchanged `stNum`, the measured interval is below `minTimeMs` or its fallback. The software-tick fallback applies a one-millisecond margin. | High-rate broadcast storm, denial of service (DoS), or malfunctioning IED transmitting excessive bursts. |
| `GOOSE_TIMING_SLOW` | `WARNING` | For an eligible sequence advance, the measured interval exceeds the previous frame's `timeAllowedToLive`. A zero TTL falls back to `maxTimeMs` multiplied by `ttl_multiplier`. | IED communication failure, fiber break, transmitter reboot, or network disruption. |

### GOOSE Timing Source

The Ethernet MAC is configured to capture a timestamp in the RX descriptor. The driver passes the timestamp with the copied GOOSE frame. The GOOSE task uses consecutive valid MAC timestamps for fast timing, slow timing, TTL expiry, and restart validation. The first accepted frame initializes its stream state. A state-number increase takes precedence over the timing checks, as do sequence anomalies.

If a MAC timestamp is unavailable, the code logs a warning and uses the millisecond `HAL_GetTick()` value captured when the frame was enqueued. The MAC counter is an unsynchronized local HCLK-based interval clock. The code handles its 63-bit rollover. Its accuracy and frame-to-descriptor association require target hardware verification.

The GOOSE `t` field is decoded into `frameTs` for alerts. It is the publisher-provided timestamp, not the gateway RX timestamp. It is not used for the interval checks. Matching can fall back from `gocbRef` to other identifiers, so stream isolation depends on the baseline and matching results.

### Configurable Parameters (`system_config.h`)

* `goose.timing_check_enabled`: Enable/disable `TIMING_FAST` and `TIMING_SLOW` checks.
* `goose.state_check_enabled`: Enable/disable `stNum`/`sqNum` state machine checks.
* `goose.baseline_check_enabled`: Enable/disable matching against SCD baseline parameters.
* `goose.min_time_fallback_ms`: Fallback minimum time interval (default 2 ms, range 1..1000 ms).
* `goose.max_time_fallback_ms`: Fallback heartbeat timeout (default 1000 ms, range 10..60000 ms).
* `goose.ttl_multiplier`: Multiplier applied to `maxTimeMs` when `timeAllowedToLive` is 0 (range 1..10).

---

## 3. Sampled Values (SV) Detection Rules

Implemented in [`Core/Src/sv.c`](../firmware/IEC61850_Security_Gateway_v0.1/Core/Src/sv.c).

| Event Type | Default Severity | Detection Condition | Security & Operational Impact |
| :--- | :--- | :--- | :--- |
| `SV_MALFORMED_FRAME` | `HIGH` | The SV parser rejects the frame structure or length. | Possible malformed frame, fuzzing, or corrupted merging unit stream. |
| `SV_UNKNOWN_CONTROL_BLOCK` | `HIGH` | Stream identifier (`svID`), APPID, or destination MAC address is not registered in the active baseline. | Rogue merging unit attached to process bus or unauthorized SV stream. |
| `SV_MAC_MISMATCH` | `HIGH` | Destination multicast MAC differs from the configured value in the SCD baseline. | Multicast stream redirection or MAC spoofing. |
| `SV_APPID_MISMATCH` | `HIGH` | 16-bit APPID does not match the baseline configuration. | Masquerading stream or merging unit misconfiguration. |
| `SV_VLAN_MISMATCH` | `HIGH` | Missing 802.1Q tag or VLAN ID does not match baseline. | Unauthorized VLAN injection or switch configuration error. |
| `SV_VLAN_PRIORITY_MISMATCH` | `WARNING` | VLAN PCP priority does not match configured baseline (typically 4 for SV). | QoS misconfiguration; high-rate SV frames may drop under heavy switch traffic. |
| `SV_SVID_MISMATCH` | `HIGH` | The `svID` string in the ASDU differs from the configured stream identifier in the baseline. | Stream hijacking, spoofing, or mismatch between SCD and MU configuration. |
| `SV_CONFREV_MISMATCH` | `HIGH` | `confRev` in ASDU differs from baseline configuration revision. | Outdated baseline or unauthorized parameter modification on merging unit. |
| `SV_NOFASDU_MISMATCH` | `HIGH` | Number of ASDUs per frame differs from the configured baseline (`nofASDU`). | Stream format mismatch; protection relays expecting 1 ASDU may misinterpret multi-ASDU frames. |
| `SV_SAMPLERATE_MISMATCH` | `HIGH` | The optional `smpRate` field differs from the configured baseline sample rate. | Merging unit clock drift, sampling frequency mismatch, or missing timing synchronization (IEEE 1588). |
| `SV_SMPCNT_GAP` | `WARNING` | The forward distance exceeds `nofASDU` but remains within the configured wrap tolerance. | Packet drop across network switch, buffer overrun, or loss of optical link. |
| `SV_SMPCNT_DUPLICATE` | `WARNING` | Consecutive SV frames arrive with identical `smpCnt` without sequence advance. | Packet reflection, duplicate network paths without PRP filtering, or frozen merging unit DSP. |
| `SV_SMPCNT_ROLLBACK` | `HIGH` | `smpCnt` decreases unexpectedly outside the valid wrap-around boundary (`smpRate - 1` → `0`). | SV replay attack, false data injection, or out-of-order packet delivery. |

### Wrap-Around & Stream Idle Handling

* **Nominal Wrap Boundary**: For a 4000 Hz stream, `smpCnt` counts from `0` to `3999` per second. A wrap from `3999` to `0` is recognized as normal and does not trigger rollback.
* **Wrap Tolerance (`wrap_boundary_tolerance`)**: Allows wrap within a tolerance window (default 100 samples) to accommodate multi-ASDU packetization.
* **Idle Timeout (`idle_timeout_ms`)**: If a stream is interrupted for longer than the idle threshold (default 1000 ms), the internal counter re-synchronizes on the next received frame without generating a spurious rollback alert.

---

## 4. MMS SCADA Protection Rules

Implemented in [`Core/Src/mms.c`](../firmware/IEC61850_Security_Gateway_v0.1/Core/Src/mms.c).

| Event Type | Default Severity | Detection Condition | Security & Operational Impact |
| :--- | :--- | :--- | :--- |
| `MMS_MALFORMED_FRAME` | `HIGH` | The parser rejects the IPv4 or TCP frame structure. It does not require every TCP segment to contain a complete TPKT/COTP message. | Protocol fuzzing, malformed exploit payloads, or corrupted packets. |
| `MMS_UNKNOWN_ENDPOINT` | `HIGH` | MMS traffic observed when no active SCD baseline is loaded. | Gateway operating without baseline configuration; cannot verify authorization. |
| `MMS_UNKNOWN_DESTINATION` | `HIGH` | Target destination IP address is not configured as an authorized MMS server in the baseline. | Probing, scanning, or unauthorized lateral movement within station bus. |
| `MMS_UNKNOWN_SOURCE` | `HIGH` | Source IP address does not match an authorized engineering workstation, SCADA client, or IED. | Rogue laptop, compromised jump host, or unauthorized external connection. |
| `MMS_UNEXPECTED_ENDPOINT` | `HIGH` | Connection targets an IED interface that is defined in the baseline as a non-MMS interface (e.g., Process Bus). | Traffic leakage between process and station buses, or routing bridge breach. |
| `MMS_UNAUTHORIZED_PORT` | `HIGH` | A classified MMS candidate targets a port other than the configured port, 8080, or 3782. Classification first requires the source or destination to match the configured MMS port. | Port evasion, non-standard backdoors, or service misconfiguration. |
| `MMS_TSEL_MISMATCH` | `WARNING` | A parsed COTP selector differs from the hard-coded expected value `0001`. | Client configuration mismatch or unauthorized client application connecting. |
| `MMS_UNAUTHORIZED_WRITE` | `CRITICAL` | The payload scan identifies byte patterns treated as an MMS write request. The implementation does not validate the target variable against a protected-object list. | **Critical Threat**: Unauthorized attempt to operate circuit breakers, trip disconnectors, or alter protective relay setpoints. |
| `MMS_CON_ANOMALY` | - | Defined in the event mapping; the current MMS processing path does not assign it. | No detection claim is made for this event. |

---

## 5. Normalized Alert Record Schema

Protocol events are submitted as `Security_AlertLog_t` records. Accepted RAM slots are candidates for writing to `0:/alerts/alerts.ndjson`; writes can fail.

### Schema Format (Newline Delimited JSON)

```json
{
  "id": "ALT-0042",
  "ts": 164289,
  "frameTs": 1729384910245,
  "proto": "GOOSE",
  "type": "GOOSE_TIMING_FAST",
  "sev": "WARNING",
  "srcMac": "00:30:A7:01:00:01",
  "dstMac": "01:0C:CD:01:00:01",
  "target": "IED1_Breaker52A/LLN0$GO$gcb01",
  "appId": "0x0001",
  "vlan": 100,
  "confRev": 1,
  "stNum": 4,
  "sqNum": 18,
  "details": "Timing anomaly: 1 ms < minTime 2 ms"
}
```

### Field Descriptions

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | String | Sequence ID formatted as `ALT-XXXX`. Startup scans the existing log for the highest ID. IDs can be reused after the log is cleared and the device restarts. |
| `ts` | Unsigned Integer | Gateway uptime timestamp in milliseconds captured during protocol enqueue, with an event-time fallback in the logger. |
| `frameTs` | Unsigned 64-bit | Publisher-provided timestamp decoded from GOOSE or SV data, rounded to milliseconds; zero when absent. For GOOSE, this is `t`, not gateway reception time. |
| `proto` | String | Protocol identifier: `"GOOSE"`, `"SV"`, or `"MMS"`. |
| `type` | String | Specific detection rule triggered (e.g. `"GOOSE_CONFREV_MISMATCH"`). |
| `sev` | String | Severity rating: `"CRITICAL"`, `"HIGH"`, `"WARNING"`, or `"INFO"`. |
| `srcMac` | String | Source MAC address (`XX:XX:XX:XX:XX:XX`) or IPv4 address. |
| `dstMac` | String | Destination MAC address or target server IPv4 address. |
| `target` | String | Logical path or identifier of target device / control block (e.g. `IED1_Breaker52A/LLN0$GO$gcb01`). |
| `appId` | String | Hex-encoded 16-bit APPID (e.g. `"0x0001"`). |
| `vlan` | Unsigned Integer | 12-bit IEEE 802.1Q VLAN ID (`0` if untagged). |
| `confRev` | Unsigned Integer | Configuration revision from frame. |
| `stNum` | Unsigned Integer | State number (GOOSE) or `0`. |
| `sqNum` | Unsigned Integer | Sequence counter (GOOSE) or sample counter `smpCnt` (Sampled Values). |
| `details` | String | Human-readable diagnostic description of the detected anomaly condition. |

### Detection and Delivery Limits

GOOSE and SV parsing failures can produce malformed-frame events. Normal traffic can produce `INFO` events. A protocol frame can fail before the parser, and alert-slot or storage errors can prevent persistence. The MMS path inspects individual Ethernet/TCP frames; it does not reassemble an MMS byte stream. An event name or severity does not prove an attack or a completed storage operation.
