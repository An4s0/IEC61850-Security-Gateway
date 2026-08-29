#!/usr/bin/env python3
"""
SV smpCnt Duplicate Scenario
Generates Sampled Values traffic with intentional duplicate sample count frames.
"""

import time
from sv import build_sv_pdu, build_sv_apdu, build_ethernet_frame, send_frame, generate_3phase_samples

def run(st, args):
    print(f"Loaded SCD: {st.get('scd_path', 'substation.scd')}")
    print("\nSelected SV stream:")
    print(f"Publisher: {st['ied']}")
    print(f"Control Block: {st['cb']}")
    print(f"svID: {st['svid']}")
    print(f"MAC: {st['dst_mac']}")
    print(f"APPID: 0x{st['appid']:04X}")
    print(f"Sample Rate: {st['smprate']} samples/sec")

    print("\nScenario: SV smpCnt Duplicate (Replay / Duplicate Packet Injection)\n")

    delay = getattr(args, "interval", 0.05)
    max_smpcnt = st["smprate"]

    smpcnt_sequence = [0, 1, 1, 2, 3]

    for smpcnt in smpcnt_sequence:
        samples = generate_3phase_samples(smpcnt, sample_rate=st["smprate"], num_channels=st["num_channels"])
        pdu = build_sv_pdu(
            svid=st["svid"],
            smpcnt=smpcnt,
            confrev=st["confrev"],
            smprate=st["smprate"],
            samples=samples,
            nofasdu=st["nofasdu"],
            smpsynch=2
        )
        apdu = build_sv_apdu(st["appid"], pdu)
        frame = build_ethernet_frame(st["src_mac"], st["dst_mac"], st["vlan_id"], st["vlan_prio"], apdu)

        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} smpCnt={smpcnt:4d}/{max_smpcnt} ({len(frame)} bytes)")
        time.sleep(delay)
