#!/usr/bin/env python3
"""
GOOSE Slow Timing Anomaly Scenario
Generates GOOSE traffic significantly slower than configured in substation.scd (exceeding timeAllowedtoLive).
"""

import time
from goose import build_goose_pdu, build_goose_apdu, build_ethernet_frame, send_frame

def run(st, args):
    expected_max_ms = st["max_time_ms"]
    expected_time_allowed_ms = expected_max_ms * 2
    slow_interval_s = getattr(args, "slow_interval_s", 2.5)
    sent_interval_ms = slow_interval_s * 1000.0

    print(f"Loaded SCD: {st.get('scd_path', 'substation.scd')}")
    print("\nSelected GOOSE stream:")
    print(f"Publisher: {st['ied']}")
    print(f"Control Block: {st['cb']}")
    print(f"MAC: {st['dst_mac']}")
    print(f"APPID: 0x{st['appid']:04X}")
    print(f"VLAN: {st['vlan_id']}")
    print(f"Configured MaxTime: {expected_max_ms}ms (timeAllowedtoLive: {expected_time_allowed_ms}ms)")

    print("\nScenario: Slow Timing Anomaly (Missed Heartbeat / Late Frame)")
    print(f"Expected Interval: <= {expected_max_ms}ms (timeAllowedtoLive: {expected_time_allowed_ms}ms)")
    print(f"Sent Interval:     {sent_interval_ms:.0f}ms (Exceeds timeAllowedtoLive -> Detection Trigger)")

    print("\nSending traffic...\n")

    stnum = 1
    sqnum = 0
    values = [False] * st["num_entries"]
    count = getattr(args, "count", 3)

    for i in range(count):
        t = time.time()
        pdu = build_goose_pdu(
            gocbref=st["gocbref"],
            time_allowed=expected_time_allowed_ms,
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
        frame = build_ethernet_frame(st["src_mac"], st["dst_mac"], st["vlan_id"], st["vlan_prio"], apdu)

        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} packet #{i+1} "
              f"stNum={stnum} sqNum={sqnum} timeAllowedtoLive={expected_time_allowed_ms}ms")
        sqnum += 1

        if i < count - 1:
            print(f"Waiting {slow_interval_s}s (> timeAllowedtoLive of {expected_time_allowed_ms}ms)...")
            time.sleep(slow_interval_s)
