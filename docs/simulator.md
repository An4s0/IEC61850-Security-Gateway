# Traffic Simulator & Test Suite

The `simulator/` directory contains the Python test suite used to generate IEC 61850 traffic and verify the gateway's detection rules.

The simulator supports GOOSE, Sampled Values (SV), and MMS traffic. It can generate both normal traffic and traffic containing specific anomalies.

---

## 1. Overview

The simulator is organized by protocol:

* **GOOSE** — 8 scenarios
* **Sampled Values (SV)** — 11 scenarios
* **MMS** — 6 scenarios

This gives a total of **25 test scenarios**.

The scenarios are designed to test the same conditions handled by the gateway IDS, making it possible to verify that expected traffic is accepted and abnormal traffic generates the correct alert.

---

## 2. Test Scenarios

### GOOSE

| Scenario                 | Purpose                                    |
| :----------------------- | :----------------------------------------- |
| `normal`                 | Sends valid GOOSE traffic                  |
| `mac_mismatch`           | Tests an unexpected destination MAC        |
| `appid_mismatch`         | Tests an invalid APPID                     |
| `vlan_mismatch`          | Tests an unexpected VLAN                   |
| `vlan_priority_mismatch` | Tests an unexpected VLAN priority          |
| `confrev_mismatch`       | Tests an unexpected configuration revision |
| `timing_fast`            | Tests packets arriving too quickly         |
| `timing_slow`            | Tests delayed GOOSE messages               |

### Sampled Values

| Scenario              | Purpose                                    |
| :-------------------- | :----------------------------------------- |
| `normal`              | Sends a valid Sampled Values stream        |
| `mac_mismatch`        | Tests an unexpected destination MAC        |
| `appid_mismatch`      | Tests an invalid APPID                     |
| `vlan_mismatch`       | Tests an unexpected VLAN                   |
| `svid_mismatch`       | Tests an unknown stream ID                 |
| `confrev_mismatch`    | Tests an unexpected configuration revision |
| `nofasdu_mismatch`    | Tests an unexpected ASDU count             |
| `sample_rate_anomaly` | Tests an unexpected sample rate            |
| `smpcnt_duplicate`    | Tests repeated sample counters             |
| `smpcnt_gap`          | Tests missing sample counters              |
| `smpcnt_rollback`     | Tests a sample counter moving backwards    |

### MMS

| Scenario              | Purpose                                            |
| :-------------------- | :------------------------------------------------- |
| `normal`              | Sends a valid MMS connection                       |
| `unknown_source`      | Tests an unknown source endpoint                   |
| `unknown_destination` | Tests an unknown destination endpoint              |
| `unexpected_endpoint` | Tests access to an endpoint not configured for MMS |
| `unauthorized_write`  | Tests an unauthorized MMS write request            |
| `tsel_mismatch`       | Tests an invalid COTP transport selector           |

---

## 3. Running the Simulator

The main runner is `simulator/run_all.py`.

### List Available Scenarios

```bash
python simulator/run_all.py --list
```

### Run All Scenarios

```bash
python simulator/run_all.py --iface "Ethernet"
```

The interface name should be replaced with the network interface used for the test.

### Select Protocols

```bash
python simulator/run_all.py --protocols GOOSE,SV
```

### Set Packet Count

```bash
python simulator/run_all.py --count 10
```

### Use a Fixed Seed

```bash
python simulator/run_all.py --seed 12345
```

A fixed seed makes randomized test execution reproducible.

---

## 4. Protocol Runners

Each protocol can also be tested separately.

### GOOSE

```bash
python simulator/goose/goose.py --all
```

### Sampled Values

```bash
python simulator/sv/sv.py smpcnt_gap --count 20
```

### MMS

```bash
python simulator/mms/mms.py unauthorized_write --count 5
```

---

## 5. Test Flow

A typical test follows this process:

1. Load the substation configuration used as the expected baseline.
2. Generate normal or anomalous protocol traffic.
3. Send the traffic through the selected network interface.
4. Allow the gateway IDS to inspect the frames.
5. Check the generated alerts against the expected result.

The simulator is intended for repeatable testing of the gateway's detection logic without requiring real substation equipment.
