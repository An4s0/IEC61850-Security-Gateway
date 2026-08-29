#!/usr/bin/env python3
"""
SV nofASDU Mismatch Scenario
Generates Sampled Values traffic with an intentionally modified nofASDU (number of ASDUs per savPdu).
"""

import time
from sv import build_sv_pdu, build_sv_apdu, build_ethernet_frame, send_frame, generate_3phase_samples

def run(st, args):
    expected_nofasdu = st["nofasdu"]
    sent_nofasdu = getattr(args, "modified_nofasdu", 2)

    print(f"Loaded SCD: {st.get('scd_path', 'substation.scd')}")
    print("\nSelected SV stream:")
    print(f"Publisher: {st['ied']}")
    print(f"Control Block: {st['cb']}")
    print(f"svID: {st['svid']}")
    print(f"MAC: {st['dst_mac']}")
    print(f"APPID: 0x{st['appid']:04X}")
    print(f"VLAN: {st['vlan_id']}")
    print(f"Configured nofASDU: {expected_nofasdu}")

    print("\nScenario: SV nofASDU Mismatch\n")
    print(f"Expected nofASDU: {expected_nofasdu}")
    print(f"Sent nofASDU:     {sent_nofasdu}")

    print("\nSending traffic...\n")

    smpcnt = 0
    max_smpcnt = st["smprate"]
    delay = getattr(args, "interval", 0.05)
    count = getattr(args, "count", 5)

    for _ in range(count):
        samples_list = [
            generate_3phase_samples(smpcnt + i, sample_rate=st["smprate"], num_channels=st["num_channels"])
            for i in range(sent_nofasdu)
        ]
        pdu = build_sv_pdu(
            svid=st["svid"],
            smpcnt=smpcnt,
            confrev=st["confrev"],
            smprate=st["smprate"],
            samples=samples_list,
            nofasdu=sent_nofasdu,
            smpsynch=2
        )
        apdu = build_sv_apdu(st["appid"], pdu)
        frame = build_ethernet_frame(st["src_mac"], st["dst_mac"], st["vlan_id"], st["vlan_prio"], apdu)

        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} nofASDU={sent_nofasdu} "
              f"(Expected: {expected_nofasdu}) ({len(frame)} bytes)")
        smpcnt = (smpcnt + sent_nofasdu) % max_smpcnt
        time.sleep(delay)
