#!/usr/bin/env python3
"""
Normal GOOSE Traffic Scenario
Generates baseline GOOSE traffic matching substation.scd configuration.
"""

import time
from goose import build_goose_pdu, build_goose_apdu, build_ethernet_frame, send_frame

def run(st, args):
    print(f"Loaded SCD: {st.get('scd_path', 'substation.scd')}")
    print("\nSelected GOOSE stream:")
    print(f"Publisher: {st['ied']}")
    print(f"Control Block: {st['cb']}")
    print(f"gocbRef: {st['gocbref']}")
    print(f"datSet: {st['datset']}")
    print(f"goID: {st['goid']}")
    print(f"MAC: {st['dst_mac']}")
    print(f"APPID: 0x{st['appid']:04X}")
    print(f"VLAN: {st['vlan_id']} (Priority: {st['vlan_prio']})")
    print(f"confRev: {st['confrev']}")
    print(f"Timing: MinTime={st['min_time_ms']}ms, MaxTime={st['max_time_ms']}ms")

    print("\nTraffic Mode: Normal Baseline")
    print("Sending traffic...\n")

    stnum = 1
    sqnum = 0
    values = [False] * st["num_entries"]
    time_allowed = st["max_time_ms"] * 2

    retransmit_schedule_ms = [
        st["min_time_ms"],
        st["min_time_ms"] * 2,
        st["min_time_ms"] * 4,
        st["min_time_ms"] * 8,
        st["max_time_ms"]
    ]
    retransmit_idx = 0

    count = getattr(args, "count", 5)
    sent_count = 0

    while True:
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
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} APPID=0x{st['appid']:04X} "
              f"stNum={stnum} sqNum={sqnum} confRev={st['confrev']} "
              f"VLAN={st['vlan_id']}:{st['vlan_prio']} ({len(frame)} bytes)")

        sqnum += 1
        sent_count += 1
        if count > 0 and sent_count >= count:
            break

        if args.interval is not None:
            delay = args.interval
        else:
            delay = retransmit_schedule_ms[min(retransmit_idx, len(retransmit_schedule_ms) - 1)] / 1000.0
            retransmit_idx += 1

        time.sleep(delay)
