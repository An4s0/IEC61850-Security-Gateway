# Traffic Simulator & Test Suite

The `simulator/` directory contains an automated, multi-protocol test suite used to generate IEC 61850 traffic and validate the gateway's detection rules.

The simulator reads the engineering baseline directly from `substation.scd` and can generate both authorized baseline traffic and deliberate security anomalies across **GOOSE (IEC 61850-8-1)**, **Sampled Values (IEC 61850-9-2LE)**, and **MMS (IEC 61850-8-1 / ISO 9506)**.

---

## 1. Overview & Architecture

The simulator test harness is designed around modular protocol packages:

```text
simulator/
├── run_all.py                 # Unified runner with seed-based random execution
├── substation.scd             # Engineering baseline SCL/SCD configuration
├── goose/                     # GOOSE protocol package
│   ├── goose.py               # Standalone runner, BER encoder, and stream loader
│   └── scenarios/             # 8 GOOSE attack & anomaly modules
├── sv/                        # Sampled Values protocol package
│   ├── sv.py                  # Standalone runner, 9-2LE encoder, and stream loader
│   └── scenarios/             # 11 SV attack & anomaly modules
└── mms/                       # MMS SCADA protocol package
    ├── mms.py                 # Standalone runner, TPKT/COTP/MMS stack, endpoint loader
    └── scenarios/             # 6 MMS attack & anomaly modules
```

A total of **25 test scenarios** are implemented:
* **GOOSE**: 8 scenarios
* **Sampled Values (SV)**: 11 scenarios
* **MMS**: 6 scenarios

---

## 2. Catalog of Test Scenarios

### GOOSE Scenarios (8)

Implemented in `simulator/goose/scenarios/`. The expected events below depend on the baseline, frame delivery, and detector state. They are not test results.

| Scenario Name | Description | Injected Anomaly | Expected Gateway Alert |
| :--- | :--- | :--- | :--- |
| `normal` | Authorized baseline GOOSE stream from SCD. | None (valid MAC, APPID, VLAN, `confRev`, timing). | `GOOSE_TRAFFIC_NORMAL` (Info) |
| `mac_mismatch` | Destination MAC does not match SCD configuration. | Changes destination MAC to `01:0C:CD:01:00:99`. | `GOOSE_MAC_MISMATCH` (High) |
| `appid_mismatch` | APPID does not match stream definition. | Changes 16-bit APPID to `0x9999`. | `GOOSE_APPID_MISMATCH` (High) |
| `vlan_mismatch` | 802.1Q VLAN tag differs from baseline. | Modifies 12-bit VLAN ID to an unconfigured value (`999`). | `GOOSE_VLAN_MISMATCH` (High) |
| `vlan_priority_mismatch` | 802.1Q PCP priority does not match baseline. | Modifies 3-bit PCP priority code point to `0`. | `GOOSE_VLAN_PRIORITY_MISMATCH` (Warning) |
| `confrev_mismatch` | Configuration revision does not match baseline. | Modifies `confRev` to an unexpected revision number. | `GOOSE_CONFREV_MISMATCH` (High) |
| `timing_fast` | Message burst arrives faster than allowed. | Requests approximately 1 ms between frames; actual intervals depend on host scheduling. | `GOOSE_TIMING_FAST` (Warning) |
| `timing_slow` | Delayed heartbeat message arrives late. | Requests a delay beyond `timeAllowedToLive`. | `GOOSE_TIMING_SLOW` (Warning) |

### Sampled Values (SV) Scenarios (11)

Implemented in `simulator/sv/scenarios/`.

| Scenario Name | Description | Injected Anomaly | Expected Gateway Alert |
| :--- | :--- | :--- | :--- |
| `normal` | Authorized 9-2LE stream from SCD. | None (valid MAC, APPID, VLAN, `svID`, `smpCnt`, `smpRate`). | `SV_TRAFFIC_NORMAL` (Info) |
| `mac_mismatch` | Destination multicast MAC differs from baseline. | Replaces destination MAC with `01:0C:CD:04:00:99`. | `SV_MAC_MISMATCH` (High) |
| `appid_mismatch` | 16-bit APPID differs from baseline. | Modifies APPID to `0x4999`. | `SV_APPID_MISMATCH` (High) |
| `vlan_mismatch` | 802.1Q VLAN ID differs from baseline. | Modifies 12-bit VLAN ID to `999`. | `SV_VLAN_MISMATCH` (High) |
| `svid_mismatch` | `svID` string differs from baseline. | Replaces `svID` with `IED4_MergingUnitMU/LLN0.UNAUTHORIZED_SVID`. | `SV_SVID_MISMATCH` (High) |
| `confrev_mismatch` | `confRev` differs from baseline configuration. | Modifies `confRev` in ASDU header. | `SV_CONFREV_MISMATCH` (High) |
| `nofasdu_mismatch` | ASDU count per frame differs from baseline. | Alters ASDU count (e.g. 2 instead of 1). | `SV_NOFASDU_MISMATCH` (High) |
| `sample_rate_anomaly` | The transmitted sample rate field differs from the baseline. | Sets a different `smpRate` value. | `SV_SAMPLERATE_MISMATCH` (High) |
| `smpcnt_gap` | Missing sample sequence counters. | Skips sample counters (e.g. `smpCnt` jumps from 10 to 25). | `SV_SMPCNT_GAP` (Warning) |
| `smpcnt_duplicate` | Repeated sample counters. | Sends multiple consecutive frames with identical `smpCnt`. | `SV_SMPCNT_DUPLICATE` (Warning) |
| `smpcnt_rollback` | Sample sequence moves backwards unexpectedly. | Decreases `smpCnt` (e.g. from 50 to 20) outside wrap boundary. | `SV_SMPCNT_ROLLBACK` (High) |

### MMS SCADA Scenarios (6)

Implemented in `simulator/mms/scenarios/`.

| Scenario Name | Description | Injected Anomaly | Expected Gateway Alert |
| :--- | :--- | :--- | :--- |
| `normal` | Authorized SCADA connection to MMS server. | None (valid client IP, server IP, port 102, COTP TSEL). | `MMS_TRAFFIC_NORMAL` (Info) |
| `unknown_source` | Connection from unauthorized client IP. | Sends traffic from an IP not in the authorized client whitelist. | `MMS_UNKNOWN_SOURCE` (High) |
| `unknown_destination` | Connection to unconfigured destination IP. | Targets an IP address not configured as an MMS server. | `MMS_UNKNOWN_DESTINATION` (High) |
| `unexpected_endpoint` | Connection to non-MMS interface. | Targets an IED interface designated as Process Bus only. | `MMS_UNEXPECTED_ENDPOINT` (High) |
| `unauthorized_write` | Unauthorized SCADA write command. | Sends a frame containing the simulator's MMS write payload. | `MMS_UNAUTHORIZED_WRITE` (Critical) |
| `tsel_mismatch` | Mismatched COTP transport selector. | Connects using an invalid Calling/Called T-Selector. | `MMS_TSEL_MISMATCH` (Warning) |

---

## 3. Running the Unified Test Runner (`run_all.py`)

`simulator/run_all.py` is the primary entry point. It loads scenarios across all selected protocols and executes them in a randomized order.

### Basic Execution

Run all 25 scenarios across GOOSE, SV, and MMS:

```bash
python simulator/run_all.py --iface "Ethernet"
```

### Reproducible Execution (`--seed`)

Pass a specific random seed to reproduce the exact scenario execution sequence:

```bash
python simulator/run_all.py --seed 12345 --iface "Ethernet"
```

### Filtering Protocols (`--protocols`)

Run only specific protocols (comma-separated list):

```bash
# Test only GOOSE and Sampled Values
python simulator/run_all.py --protocols GOOSE,SV --iface "Ethernet"

# Test only MMS SCADA traffic
python simulator/run_all.py --protocols MMS
```

### Setting Packet Count (`--count`)

Specify how many packets or requests to send per scenario:

```bash
python simulator/run_all.py --count 10 --iface "Ethernet"
```

### Listing Available Scenarios (`--list`)

Display all available scenarios across all protocols:

```bash
python simulator/run_all.py --list
```

### Specifying Custom SCD Configuration (`--scd`)

Run the test suite against a different substation baseline:

```bash
python simulator/run_all.py --scd path/to/custom_substation.scd --iface "Ethernet"
```

---

## 4. Execution Summary Report

`run_all.py` generates a terminal report. The following output illustrates the format; it is not a recorded verification result:

```text
================================================================================
                     IEC 61850 SIMULATION SUMMARY
================================================================================
  Execution Order & Results (Seed: 12345):
  #    Protocol   Scenario Name                Status     Duration   Details
  ----------------------------------------------------------------------------
  1    GOOSE      normal                       PASS       0.15s     
  2    SV         smpcnt_gap                   PASS       0.21s     
  3    MMS        unauthorized_write           PASS       0.34s     
  4    GOOSE      timing_fast                  PASS       0.08s     
  5    SV         svid_mismatch                PASS       0.18s     
  ...
  ----------------------------------------------------------------------------
  Total: 25 | Passed: 25 | Failed: 0 | Total Duration: 5.12s
  Overall Status: ALL SCENARIOS PASSED SUCCESSFULLY
================================================================================
```

A scenario is marked `PASS` when its Python function returns without an exception. This does not confirm transmission, gateway reception, detection, persistence, or dashboard display. The simulator can report simulated transmission when it cannot send a frame. Measure those outcomes separately on the target network and gateway.

---

## 5. Individual Protocol Runners

Each protocol package can also be executed independently for focused debugging.

### GOOSE Runner (`simulator/goose/goose.py`)

```bash
# Run all GOOSE scenarios
python simulator/goose/goose.py --all --iface "Ethernet"

# Run a specific scenario with custom packet count
python simulator/goose/goose.py timing_fast --count 20 --iface "Ethernet"

# List available GOOSE scenarios
python simulator/goose/goose.py --list
```

### Sampled Values Runner (`simulator/sv/sv.py`)

```bash
# Run all SV scenarios
python simulator/sv/sv.py --all --iface "Ethernet"

# Run sequence rollback anomaly with 50 samples
python simulator/sv/sv.py smpcnt_rollback --count 50 --iface "Ethernet"

# List available SV scenarios
python simulator/sv/sv.py --list
```

### MMS Runner (`simulator/mms/mms.py`)

```bash
# Run all MMS scenarios
python simulator/mms/mms.py --all

# Run unauthorized SCADA write test against target IED
python simulator/mms/mms.py unauthorized_write --target-ied "IED1_Breaker52A" --count 5

# List available MMS scenarios
python simulator/mms/mms.py --list
```

---

## 6. End-to-End Validation Workflow

For an end-to-end test, use a controlled network and a configured gateway. The steps below describe the workflow; they do not establish a test result:

1. **Upload Baseline**: Open the Web Console (`http://<gateway-ip>/`) in a browser and upload `simulator/substation.scd`.
2. **Verify Configuration**: Check that the dashboard indicates **Configuration Loaded** and displays the active IED, GOOSE, SV, and MMS stream counts.
3. **Open Dashboard Overview**: Navigate to the live console view to monitor real-time alerts.
4. **Execute Simulation**: Run `python simulator/run_all.py --iface "<network-interface>"`.
5. **Verify Alert Reception**:
   * Compare each scenario with the expected event in the catalog. Normal scenarios are not threat alerts.
   * Verify that `MMS_UNAUTHORIZED_WRITE` appears with `CRITICAL` severity (dark red).
   * Compare transmitted frames, gateway counters, and stored records. Inspect queue and storage errors for differences.
6. **Export Data**: Click **Export CSV** in the Web Console to save the alert log for analysis or auditing.

### Timing and Test Limitations

The GOOSE simulator builds the `t` field from `time.time()` in each transmission loop. That field is not the gateway RX timestamp. Host scheduling and `time.sleep()` do not guarantee the requested interval. Use a packet capture to measure actual transmitted intervals, and compare them with gateway observations.

The current firmware has finite protocol pools, queues, alert slots, and storage throughput. A simulator `PASS` does not prove zero loss or one persisted record per frame. The MMS detector processes individual frames without TCP stream reassembly. Hardware timing accuracy, queue pressure, persistence, and SSE delivery require separate measurement.
