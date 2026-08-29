#!/usr/bin/env python3
"""
GOOSE VLAN ID Mismatch Scenario
Generates GOOSE traffic with an intentionally modified VLAN ID.
"""

import time
from goose import build_goose_pdu, build_goose_apdu, build_ethernet_frame, send_frame

def run(st, args):
    expected_vlan = st["vlan_id"]
    sent_vlan = getattr(args, "modified_vlan", 999)

    print(f"Loaded SCD: {st.get('scd_path', 'substation.scd')}")
    print("\nSelected GOOSE stream:")
    print(f"Publisher: {st['ied']}")
    print(f"Control Block: {st['cb']}")
    print(f"MAC: {st['dst_mac']}")
    print(f"APPID: 0x{st['appid']:04X}")
    print(f"VLAN: {expected_vlan}")

    print("\nScenario: VLAN ID Mismatch\n")
    print(f"Expected VLAN ID: {expected_vlan}")
    print(f"Sent VLAN ID:     {sent_vlan}")

    print("\nSending traffic...\n")

    stnum = 1
    sqnum = 0
    values = [False] * st["num_entries"]
    time_allowed = st["max_time_ms"] * 2
    count = getattr(args, "count", 5)

    for _ in range(count):
        t = time.time()
        pdu = build_goose_pdu(
            gocbref=st["gocbref"],
            time_allowed=time_allowed,
            datset=st["datset"],
            goid=st["goid"],
            t=t,
            stnum=stnum,
            sqnum=sqnum,
            test=False,
            confrev=st["confrev"],
            ndscom=False,
            values=values
        )
        apdu = build_goose_apdu(st["appid"], pdu)
        frame = build_ethernet_frame(st["src_mac"], st["dst_mac"], sent_vlan, st["vlan_prio"], apdu)

        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} VLAN={sent_vlan} "
              f"(Expected: {expected_vlan}) APPID=0x{st['appid']:04X} stNum={stnum} sqNum={sqnum}")
        sqnum += 1
        time.sleep(0.1)
