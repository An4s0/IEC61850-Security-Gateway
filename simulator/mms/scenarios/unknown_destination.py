#!/usr/bin/env python3
"""
MMS Unknown Destination Scenario
Generates MMS traffic directed toward an unconfigured / unknown destination IP not present in substation.scd via raw packet injection.
"""

import time
from mms import build_cotp_connection_request, build_mms_frame, send_frame, MMS_DEFAULT_PORT

def run(endpoints, args):
    client_ied = getattr(args, "client_ied", "IED5_StationCtrl")
    port = getattr(args, "port", MMS_DEFAULT_PORT)
    interval = getattr(args, "interval", 0.05)
    count = getattr(args, "count", 3)
    modified_dst = getattr(args, "modified_dest_ip", "192.168.10.200")
    modified_mac = getattr(args, "modified_dest_mac", "00:50:56:01:00:FE")

    server_ep = next((ep for ep in endpoints if ep["ied"] == "IED1_Breaker52A"), endpoints[0])
    client_ep = next((ep for ep in endpoints if ep["ied"] == client_ied), endpoints[-1])

    expected_dst_ip = server_ep["ip"]
    client_ip = client_ep["ip"]
    client_mac = client_ep.get("mac", "00:50:56:01:00:15")

    print(f"Loaded SCD: {server_ep.get('scd_path', 'substation.scd')}")
    print("\nSelected MMS Endpoints:")
    print(f"Source (Client):          {client_ep['ied']} ({client_ip})")
    print(f"Expected Server Endpoint: {server_ep['ied']} ({expected_dst_ip}:{port})")

    print("\nScenario: MMS Unknown Destination IP\n")
    print(f"Expected Destination IP: {expected_dst_ip}:{port} ({server_ep['ied']})")
    print(f"Sent Destination IP:     {modified_dst}:{port} (Unknown / Unconfigured Endpoint)")

    print("\nSending traffic...\n")

    pdu = build_cotp_connection_request(src_tsel=client_ep["tsel"], dst_tsel="0001")
    frame = build_mms_frame(
        src_mac=client_mac,
        dst_mac=modified_mac,
        src_ip=client_ip,
        dst_ip=modified_dst,
        src_port=49152,
        dst_port=port,
        payload=pdu
    )

    for i in range(count):
        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {client_ip} -> {modified_dst}:{port} (Unknown destination, {len(frame)} bytes)")
        time.sleep(interval)
