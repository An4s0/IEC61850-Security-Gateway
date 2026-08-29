#!/usr/bin/env python3
"""
Normal Sampled Values (SV) Traffic Scenario
Generates baseline Sampled Values traffic matching substation.scd configuration.
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
    print(f"VLAN: {st['vlan_id']} (Priority: {st['vlan_prio']})")
    print(f"Sample Rate: {st['smprate']} samples/sec")
    print(f"nofASDU: {st['nofasdu']}")
    print(f"confRev: {st['confrev']}")
    print(f"Channels: {st['num_channels']} (3-phase Current + 3-phase Voltage)")

    print("\nTraffic Mode: Normal Baseline")
    print("Sending traffic...\n")

    smpcnt = 0
    max_smpcnt = st["smprate"]
    delay = getattr(args, "interval", 0.05)
    count = getattr(args, "count", 5)
    sent_count = 0

    while True:
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
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} APPID=0x{st['appid']:04X} "
              f"smpCnt={smpcnt:4d}/{max_smpcnt} confRev={st['confrev']} "
              f"VLAN={st['vlan_id']}:{st['vlan_prio']} ({len(frame)} bytes)")

        smpcnt = (smpcnt + 1) % max_smpcnt
        sent_count += 1
        if count > 0 and sent_count >= count:
            break

        time.sleep(delay)
