#!/usr/bin/env python3
"""
SV VLAN ID Mismatch Scenario
Generates Sampled Values traffic with an intentionally modified VLAN ID.
"""

import time
from sv import build_sv_pdu, build_sv_apdu, build_ethernet_frame, send_frame, generate_3phase_samples

def run(st, args):
    expected_vlan = st["vlan_id"]
    sent_vlan = getattr(args, "modified_vlan", 999)

    print(f"Loaded SCD: {st.get('scd_path', 'substation.scd')}")
    print("\nSelected SV stream:")
    print(f"Publisher: {st['ied']}")
    print(f"Control Block: {st['cb']}")
    print(f"svID: {st['svid']}")
    print(f"MAC: {st['dst_mac']}")
    print(f"APPID: 0x{st['appid']:04X}")
    print(f"VLAN: {expected_vlan}")

    print("\nScenario: SV VLAN ID Mismatch\n")
    print(f"Expected VLAN ID: {expected_vlan}")
    print(f"Sent VLAN ID:     {sent_vlan}")

    print("\nSending traffic...\n")

    smpcnt = 0
    max_smpcnt = st["smprate"]
    delay = getattr(args, "interval", 0.05)
    count = getattr(args, "count", 5)

    for _ in range(count):
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
        frame = build_ethernet_frame(st["src_mac"], st["dst_mac"], sent_vlan, st["vlan_prio"], apdu)

        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} VLAN={sent_vlan} "
              f"(Expected: {expected_vlan}) APPID=0x{st['appid']:04X} smpCnt={smpcnt:4d}/{max_smpcnt}")
        smpcnt = (smpcnt + 1) % max_smpcnt
        time.sleep(delay)
