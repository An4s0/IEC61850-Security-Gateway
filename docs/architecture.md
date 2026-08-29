# System Architecture

This document gives a high-level overview of the software architecture of the IEC 61850 Security Gateway.

---

## 1. Overview

The gateway is a passive IDS that monitors Ethernet traffic from an IEC 61850 substation network.

Incoming traffic is classified by protocol and passed to the corresponding IDS module. Each module checks the traffic against the active SCD-based baseline and generates an alert when an unexpected condition is detected.

The main components are:

* Ethernet packet capture and classification
* GOOSE, Sampled Values, and MMS monitoring
* SCD-based configuration
* Security alert logging
* Web API and dashboard
* FreeRTOS tasks for concurrent processing

---

## 2. Packet Processing

Received Ethernet frames are inspected by the packet classifier.

The classifier identifies:

* **GOOSE** using EtherType `0x88B8`
* **Sampled Values** using EtherType `0x88BA`
* **MMS** using IPv4/TCP traffic on port `102`
* **802.1Q VLAN** tagged versions of these protocols

Matching frames are passed to their corresponding IDS processing task. Other IPv4 traffic can continue through the normal network stack.

---

## 3. IDS Processing

Each supported protocol has its own monitoring logic.

### GOOSE

The GOOSE monitor checks protocol fields and compares them with the configured baseline. It also monitors sequence numbers and message timing to identify abnormal behavior.

### Sampled Values

The SV monitor checks stream parameters such as the destination, APPID, VLAN, `svID`, configuration revision, sample rate, and sample sequence.

### MMS

The MMS monitor checks TCP connections and MMS traffic against the configured endpoints and monitors for unauthorized write operations.

When a rule is triggered, the IDS creates a security alert containing information about the event.

---

## 4. SCD Configuration

The system uses an SCD/SCL file as the source of the authorized substation configuration.

The web interface reads the SCD file and converts the required configuration into JSON. The JSON configuration is uploaded to the gateway and stored on the SD card.

The configuration service then loads the new configuration and replaces the active baseline without requiring a firmware restart.

This baseline is used by the GOOSE, SV, and MMS monitoring modules when validating traffic.

---

## 5. FreeRTOS Tasks

The firmware uses FreeRTOS to separate the main processing functions.

The main tasks handle:

* Ethernet packet reception
* GOOSE monitoring
* Sampled Values monitoring
* MMS monitoring
* SCD configuration storage and loading
* Network and web services

Queues are used to pass captured frames between the packet reception and IDS tasks. This keeps packet reception separate from the protocol analysis.

---

## 6. Alert Handling

When an IDS rule detects an anomaly, the security subsystem creates an alert.

Alerts are:

1. Written to the SD card for persistent storage.
2. Sent to the web interface through the SSE connection for real-time display.

The web interface can also request previously stored alerts and clear the alert history.

---

## 7. Web Interface

The gateway provides a browser-based interface for monitoring the system.

The web interface allows the operator to:

* Upload an SCD configuration
* View the active configuration
* Monitor security alerts in real time
* Filter alerts by protocol
* View historical alerts
* Export alert data as CSV

The dashboard communicates with the gateway through the HTTP API.

---

## 8. Overall Flow

The overall processing flow is:

**Network Traffic → Packet Classification → Protocol IDS → Baseline Check → Alert Generation → SD Card / Web Dashboard**

The architecture keeps packet processing, protocol analysis, configuration management, and alert handling as separate components so that each part can operate independently.
