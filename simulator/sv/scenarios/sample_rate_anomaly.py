#!/usr/bin/env python3
"""
SV Sample Rate Anomaly Scenario
Generates Sampled Values traffic with an intentionally modified sample rate (smpRate field and pacing).
"""

import time
from sv import build_sv_pdu, build_sv_apdu, build_ethernet_frame, send_frame, generate_3phase_samples

def run(st, args):
    expected_rate = st["smprate"]
    sent_rate = getattr(args, "modified_rate", 1000)

    print(f"Loaded SCD: {st.get('scd_path', 'substation.scd')}")
    print("\nSelected SV stream:")
    print(f"Publisher: {st['ied']}")
    print(f"Control Block: {st['cb']}")
    print(f"svID: {st['svid']}")
    print(f"MAC: {st['dst_mac']}")
    print(f"APPID: 0x{st['appid']:04X}")
    print(f"Configured Sample Rate: {expected_rate} samples/sec")

    print("\nScenario: SV Sample Rate Anomaly\n")
    print(f"Expected Sample Rate: {expected_rate} samples/sec")
    print(f"Sent Sample Rate:     {sent_rate} samples/sec")

    print("\nSending traffic...\n")

    smpcnt = 0
    max_smpcnt = sent_rate
    delay = getattr(args, "interval", 0.05)
    count = getattr(args, "count", 5)

    for _ in range(count):
        samples = generate_3phase_samples(smpcnt, sample_rate=sent_rate, num_channels=st["num_channels"])
        pdu = build_sv_pdu(
            svid=st["svid"],
            smpcnt=smpcnt,
            confrev=st["confrev"],
            smprate=sent_rate,
            samples=samples,
            nofasdu=st["nofasdu"],
            smpsynch=2
        )
        apdu = build_sv_apdu(st["appid"], pdu)
        frame = build_ethernet_frame(st["src_mac"], st["dst_mac"], st["vlan_id"], st["vlan_prio"], apdu)

        sent = send_frame(frame, iface=args.iface)
        status_str = "TX" if sent else "Simulated TX"
        print(f"[{status_str}] {st['ied']} -> {st['dst_mac']} smpRate={sent_rate} "
              f"(Expected: {expected_rate}) smpCnt={smpcnt:4d}/{max_smpcnt}")
        smpcnt = (smpcnt + 1) % max_smpcnt
        time.sleep(delay)
