#!/usr/bin/env python3
"""
MMS Unknown Source Scenario
Generates MMS traffic originating from an unconfigured / unknown source IP via raw packet injection.
"""

import time
from mms import build_cotp_connection_request, build_mms_frame, send_frame, MMS_DEFAULT_PORT

def run(endpoints, args):
    target_ied = getattr(args, "target_ied", "IED1_Breaker52A")
    port = getattr(args, "port", MMS_DEFAULT_PORT)
    interval = getattr(args, "interval", 0.05)
    count = getattr(args, "count", 3)
    modified_src = getattr(args, "modified_source_ip", "192.168.10.99")
    modified_mac = getattr(args, "modified_source_mac", "00:50:56:01:00:99")

    server_ep = next((ep for ep in endpoints if ep["ied"] == target_ied and ep["has_server"]), endpoints[0])
    client_ep = next((ep for ep in endpoints if ep["ied"] == "IED5_StationCtrl"), endpoints[-1])

    expected_src_ip = client_ep["ip"]
    target_ip = server_ep["ip"]
    target_mac = server_ep.get("mac", "00:50:56:01:00:11")

    print(f"Loaded SCD: {server_ep.get('scd_path', 'substation.scd')}")
    print("\nSelected MMS Endpoints:")
    print(f"Expected Client:      {client_ep['ied']} ({expected_src_ip})")
    print(f"Destination (Server): {server_ep['ied']} ({target_ip}:{port})")

    print("\nScenario: MMS Unknown Source IP\n")
    print(f"Expected Source IP: {expected_src_ip} ({client_ep['ied']})")
    print(f"Sent Source IP:     {modified_src} (Unknown / Unconfigured Endpoint)")

    print("\nSending traffic...\n")

    pdu = build_cotp_connection_request(src_tsel=client_ep["tsel"], dst_tsel=server_ep["tsel"])
    frame = build_mms_frame(
        src_mac=modified_mac,
        dst_mac=target_mac,
        src_ip=modified_src,
        dst_ip=target_ip,
        src_port=49152,
        dst_port=port,
        payload=pdu
    )

    for i in range(count):
        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {modified_src} (unauthorized source) -> {target_ip}:{port} ({len(frame)} bytes)")
        time.sleep(interval)
