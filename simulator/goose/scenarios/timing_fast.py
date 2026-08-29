#!/usr/bin/env python3
"""
GOOSE Fast Timing Anomaly Scenario
Generates GOOSE traffic significantly faster than configured in substation.scd.
"""

import time
from goose import build_goose_pdu, build_goose_apdu, build_ethernet_frame, send_frame

def run(st, args):
    fast_interval_ms = getattr(args, "fast_interval_ms", 1.0)
    delay = fast_interval_ms / 1000.0

    print(f"Loaded SCD: {st.get('scd_path', 'substation.scd')}")
    print("\nSelected GOOSE stream:")
    print(f"Publisher: {st['ied']}")
    print(f"Control Block: {st['cb']}")
    print(f"MAC: {st['dst_mac']}")
    print(f"APPID: 0x{st['appid']:04X}")
    print(f"VLAN: {st['vlan_id']}")
    print(f"Configured Timing: MinTime={st['min_time_ms']}ms, MaxTime={st['max_time_ms']}ms")

    print("\nScenario: Fast Timing Anomaly (Abnormally High Frequency / Flood)")
    print(f"Expected Timing: MinTime={st['min_time_ms']}ms, MaxTime={st['max_time_ms']}ms")
    print(f"Sent Timing:     Interval={fast_interval_ms}ms (Continuous rapid burst)")

    print("\nSending traffic...\n")

    stnum = 1
    sqnum = 0
    values = [False] * st["num_entries"]
    time_allowed = st["max_time_ms"] * 2
    count = getattr(args, "count", 10)

    for i in range(count):
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
        frame = build_ethernet_frame(st["src_mac"], st["dst_mac"], st["vlan_id"], st["vlan_prio"], apdu)

        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} burst #{i+1} "
              f"stNum={stnum} sqNum={sqnum} interval={fast_interval_ms}ms")
        sqnum += 1
        time.sleep(delay)
