#!/usr/bin/env python3
"""
MMS Unexpected Endpoint / Interface Scenario
Generates MMS traffic directed toward an invalid interface/endpoint (e.g. IED4 Process Bus interface P1 which is SV-only, or an unexpected port) via raw packet injection.
"""

import time
from mms import build_cotp_connection_request, build_mms_frame, send_frame, MMS_DEFAULT_PORT

def run(endpoints, args):
    client_ied = getattr(args, "client_ied", "IED5_StationCtrl")
    unexpected_port = getattr(args, "unexpected_port", None)
    interval = getattr(args, "interval", 0.05)
    count = getattr(args, "count", 3)

    unexpected_ep = next((ep for ep in endpoints if not ep.get("has_server", False)), None)
    if unexpected_ep is None:
        unexpected_ep = next((ep for ep in endpoints if ep.get("ap") == "P1"), None)

    target_ied = unexpected_ep["ied"] if unexpected_ep is not None else "IED4_MergingUnit"
    expected_ep = next((ep for ep in endpoints if ep["ied"] == target_ied and ep.get("has_server", False)), None)
    if expected_ep is None:
        expected_ep = next((ep for ep in endpoints if ep["ied"] == target_ied and ep.get("ap") == "S1"), endpoints[0])

    client_ep = next((ep for ep in endpoints if ep["ied"] == client_ied), endpoints[-1])

    if unexpected_ep is None:
        print("Required non-MMS endpoint configuration (e.g. Process Bus interface) not found in SCD.")
        return

    expected_ip = expected_ep["ip"]
    expected_port = MMS_DEFAULT_PORT
    sent_ip = unexpected_ep["ip"]
    sent_port = unexpected_port if unexpected_port is not None else MMS_DEFAULT_PORT
    sent_mac = unexpected_ep.get("mac", "00:50:56:01:00:14")
    client_ip = client_ep["ip"]
    client_mac = client_ep.get("mac", "00:50:56:01:00:15")

    print(f"Loaded SCD: {expected_ep.get('scd_path', 'substation.scd')}")
    print("\nSelected MMS Endpoints:")
    print(f"Source (Client): {client_ep['ied']} ({client_ip})")
    print(f"Target IED:      {target_ied}")

    print("\nScenario: MMS Unexpected Endpoint / Interface Anomaly\n")
    print(f"Expected Endpoint: {expected_ip}:{expected_port} ({expected_ep['ied']} AP={expected_ep['ap']} Subnetwork={expected_ep['subnetwork']} - MMS Allowed)")
    print(f"Sent Endpoint:     {sent_ip}:{sent_port} ({unexpected_ep['ied']} AP={unexpected_ep['ap']} Subnetwork={unexpected_ep['subnetwork']} - Process Bus SV Only, MMS Unauthorized)")

    print("\nSending traffic...\n")

    pdu = build_cotp_connection_request(src_tsel=client_ep["tsel"], dst_tsel="0001")
    frame = build_mms_frame(
        src_mac=client_mac,
        dst_mac=sent_mac,
        src_ip=client_ip,
        dst_ip=sent_ip,
        src_port=49152,
        dst_port=sent_port,
        payload=pdu
    )

    for i in range(count):
        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {client_ip} -> {sent_ip}:{sent_port} (Non-MMS Interface, {len(frame)} bytes)")
        time.sleep(interval)
