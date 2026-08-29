# Intrusion Detection Rules

This document summarizes the detection rules implemented by the IEC 61850 Security Gateway IDS for GOOSE, Sampled Values (SV), and MMS traffic.

> **Important:** The gateway operates as a passive IDS. Detected anomalies are logged to the SD card and streamed to connected operators through SSE. The gateway does not block, drop, filter, or modify network traffic.

---

## 1. GOOSE Detection

Implemented in `Core/Src/goose.c`.

| Event                          | Severity       | Detection Condition                                                                  |
| :----------------------------- | :------------- | :----------------------------------------------------------------------------------- |
| `GOOSE_MALFORMED_FRAME`        | HIGH           | Invalid frame length, APDU structure, ASN.1 tag, or BER encoding.                    |
| `GOOSE_UNKNOWN_CONTROL_BLOCK`  | HIGH           | `gocbRef`, `goID`, APPID, or destination MAC does not match the active SCD baseline. |
| `GOOSE_MAC_MISMATCH`           | HIGH           | Destination MAC differs from the configured GOOSE stream.                            |
| `GOOSE_APPID_MISMATCH`         | HIGH           | APPID differs from the configured value.                                             |
| `GOOSE_VLAN_MISMATCH`          | HIGH           | VLAN ID or VLAN tagging differs from the baseline.                                   |
| `GOOSE_VLAN_PRIORITY_MISMATCH` | WARNING        | VLAN PCP differs from the configured priority.                                       |
| `GOOSE_CONFREV_MISMATCH`       | HIGH           | `confRev` differs from the configured revision.                                      |
| `GOOSE_STATE_ANOMALY`          | HIGH / WARNING | Unexpected `stNum`/`sqNum` rollback, duplication, or replay-like behavior.           |
| `GOOSE_TIMING_FAST`            | WARNING        | Inter-arrival time is below the configured minimum transmission interval.            |
| `GOOSE_TIMING_SLOW`            | WARNING        | Inter-arrival time exceeds the configured heartbeat/TTL interval.                    |

---

## 2. Sampled Values Detection

Implemented in `Core/Src/sv.c`.

| Event                       | Severity | Detection Condition                                                       |
| :-------------------------- | :------- | :------------------------------------------------------------------------ |
| `SV_MALFORMED_FRAME`        | HIGH     | Invalid frame length, APDU structure, or ASN.1 encoding.                  |
| `SV_UNKNOWN_CONTROL_BLOCK`  | HIGH     | `svID`, APPID, or destination MAC does not match the active SCD baseline. |
| `SV_MAC_MISMATCH`           | HIGH     | Destination MAC differs from the configured SV stream.                    |
| `SV_APPID_MISMATCH`         | HIGH     | APPID differs from the configured value.                                  |
| `SV_VLAN_MISMATCH`          | HIGH     | VLAN ID or VLAN tagging differs from the baseline.                        |
| `SV_VLAN_PRIORITY_MISMATCH` | WARNING  | VLAN PCP differs from the configured priority.                            |
| `SV_SVID_MISMATCH`          | HIGH     | `svID` differs from the configured stream identifier.                     |
| `SV_CONFREV_MISMATCH`       | HIGH     | `confRev` differs from the configured revision.                           |
| `SV_NOFASDU_MISMATCH`       | HIGH     | ASDU count differs from the configured value.                             |
| `SV_SAMPLERATE_MISMATCH`    | HIGH     | `smpRate` differs from the configured sampling rate.                      |
| `SV_SMPCNT_DUPLICATE`       | WARNING  | `smpCnt` is repeated without advancing.                                   |
| `SV_SMPCNT_ROLLBACK`        | HIGH     | `smpCnt` decreases unexpectedly outside the valid wrap-around condition.  |
| `SV_SMPCNT_GAP`             | WARNING  | `smpCnt` advances by more than the expected number of samples.            |

---

## 3. MMS Detection

Implemented in `Core/Src/mms.c`.

| Event                     | Severity | Detection Condition                                                        |
| :------------------------ | :------- | :------------------------------------------------------------------------- |
| `MMS_MALFORMED_FRAME`     | HIGH     | Invalid IPv4/TCP header or truncated packet structure.                     |
| `MMS_UNKNOWN_ENDPOINT`    | HIGH     | MMS traffic is received without a valid active baseline.                   |
| `MMS_UNKNOWN_DESTINATION` | HIGH     | Destination IP is not configured as an authorized MMS server.              |
| `MMS_UNKNOWN_SOURCE`      | HIGH     | Source IP is not an authorized client or SCADA endpoint.                   |
| `MMS_UNEXPECTED_ENDPOINT` | HIGH     | Connection targets a known device that is not configured as an MMS server. |
| `MMS_UNAUTHORIZED_PORT`   | HIGH     | MMS traffic uses an unauthorized TCP destination port.                     |
| `MMS_TSEL_MISMATCH`       | WARNING  | COTP transport selectors differ from the configured baseline.              |
| `MMS_UNAUTHORIZED_WRITE`  | HIGH     | MMS Write Request is detected for a protected control operation.           |

---

## 4. Alert Record

Detected events are normalized into `Security_AlertLog_t` and persisted as JSON Lines in `0:/alerts.json`.

The record contains:

* Local and frame timestamps
* Protocol and severity
* Event identifier
* Source and destination MAC/IP
* Target IED or control block
* APPID / TCP port
* VLAN ID
* Configuration revision
* GOOSE state/sequence or SV sample counter
* Diagnostic details
* Operator recommendation

Each alert is also streamed to connected dashboard clients through Server-Sent Events (SSE).
