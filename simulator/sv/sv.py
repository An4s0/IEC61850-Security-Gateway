#!/usr/bin/env python3
"""
IEC 61850 Sampled Values (SV) Traffic Generator & Scenario Runner
Entry point for running normal Sampled Values traffic and security test scenarios from substation.scd.
"""

import argparse
import importlib
import math
import os
import struct
import sys
import time
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

SV_ETHERTYPE = 0x88BA

def ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    enc = []
    while length:
        enc.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(enc)]) + bytes(enc)

def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value

def ber_int(tag: int, val: int) -> bytes:
    if val == 0:
        return ber_tlv(tag, b"\x00")
    length = (val.bit_length() + 8) // 8
    b = val.to_bytes(length, "big", signed=True)
    return ber_tlv(tag, b)

def ber_str(tag: int, val: str) -> bytes:
    return ber_tlv(tag, val.encode("utf-8"))

def build_sv_asdu(svid, smpcnt, confrev, smprate, samples, smpsynch=2):
    asdu_body = b""
    asdu_body += ber_str(0x80, svid)
    asdu_body += ber_int(0x82, smpcnt)
    asdu_body += ber_int(0x83, confrev)
    asdu_body += ber_int(0x85, smpsynch)
    if smprate is not None:
        asdu_body += ber_int(0x86, smprate)

    sample_bytes = b""
    for val, q in samples:
        sample_bytes += struct.pack(">iI", int(val), int(q))
    asdu_body += ber_tlv(0x87, sample_bytes)
    return ber_tlv(0x30, asdu_body)

def build_sv_pdu(svid, smpcnt, confrev, smprate, samples, nofasdu=1, smpsynch=2):
    if isinstance(samples, list) and len(samples) > 0 and isinstance(samples[0], list):
        asdu_bytes = b""
        for i in range(nofasdu):
            s = samples[i % len(samples)]
            asdu_bytes += build_sv_asdu(svid, smpcnt + i, confrev, smprate, s, smpsynch)
        seq_asdu = ber_tlv(0xA2, asdu_bytes)
    else:
        single_asdu = build_sv_asdu(svid, smpcnt, confrev, smprate, samples, smpsynch)
        seq_asdu = ber_tlv(0xA2, single_asdu * nofasdu)
    sav_body = ber_int(0x80, nofasdu) + seq_asdu
    return ber_tlv(0x60, sav_body)

def build_sv_apdu(appid, pdu_bytes):
    length = 8 + len(pdu_bytes)
    header = struct.pack(">HHHH", appid, length, 0x0000, 0x0000)
    return header + pdu_bytes

def build_ethernet_frame(src_mac, dst_mac, vlan_id, vlan_prio, payload):
    dst = bytes.fromhex(dst_mac.replace(":", "").replace("-", ""))
    src = bytes.fromhex(src_mac.replace(":", "").replace("-", ""))
    if vlan_id is not None and vlan_id > 0:
        tci = ((vlan_prio & 0x7) << 13) | (vlan_id & 0x0FFF)
        hdr = dst + src + struct.pack(">HHH", 0x8100, tci, SV_ETHERTYPE)
    else:
        hdr = dst + src + struct.pack(">H", SV_ETHERTYPE)
    return hdr + payload

def send_frame(frame_bytes, iface=None):
    try:
        from scapy.all import sendp, Ether
        eth = Ether(frame_bytes)
        sendp(eth, iface=iface, verbose=False)
        return True
    except ImportError:
        pass
    except Exception:
        return False

    import socket
    if hasattr(socket, "AF_PACKET"):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((iface or "eth0", 0))
            s.send(frame_bytes)
            s.close()
            return True
        except Exception:
            return False
    return False

def generate_3phase_samples(sample_idx, sample_rate=4000, freq=50.0, i_peak=1000, v_peak=10000, num_channels=6):
    t = sample_idx / float(sample_rate)
    omega = 2.0 * math.pi * freq

    ia = int(i_peak * math.sin(omega * t))
    ib = int(i_peak * math.sin(omega * t - 2.0 * math.pi / 3.0))
    ic = int(i_peak * math.sin(omega * t + 2.0 * math.pi / 3.0))

    va = int(v_peak * math.sin(omega * t))
    vb = int(v_peak * math.sin(omega * t - 2.0 * math.pi / 3.0))
    vc = int(v_peak * math.sin(omega * t + 2.0 * math.pi / 3.0))

    all_vals = [ia, ib, ic, va, vb, vc]
    return [(all_vals[i], 0) for i in range(num_channels)]

def find_scd_file(specified_path=None):
    candidates = []
    if specified_path:
        candidates.append(specified_path)
    candidates.extend([
        "substation.scd",
        os.path.join(SCRIPT_DIR, "substation.scd"),
        os.path.join(SCRIPT_DIR, "..", "substation.scd"),
        os.path.join(SCRIPT_DIR, "..", "..", "substation.scd"),
    ])
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    return "substation.scd"

def load_scd_sv_streams(scd_path=None):
    resolved_scd = find_scd_file(scd_path)
    if not os.path.exists(resolved_scd):
        print(f"Error: SCD file not found: {resolved_scd}")
        sys.exit(1)

    tree = ET.parse(resolved_scd)
    root = tree.getroot()
    ns = {"scl": "http://www.iec.ch/61850/2003/SCL"}

    streams = []
    for ap in root.findall(".//scl:ConnectedAP", ns):
        ied_name = ap.attrib.get("iedName", "")
        src_mac_el = ap.find("scl:Private[@type='SecurityGateway-SourceMAC']", ns)
        src_mac = src_mac_el.text.replace("-", ":") if src_mac_el is not None else "00:30:A7:01:00:04"

        for smv in ap.findall("scl:SMV", ns):
            cb_name = smv.attrib.get("cbName", "")
            ld_inst = smv.attrib.get("ldInst", "")

            mac_el = smv.find("scl:Address/scl:P[@type='MAC-Address']", ns)
            appid_el = smv.find("scl:Address/scl:P[@type='APPID']", ns)
            vlan_el = smv.find("scl:Address/scl:P[@type='VLAN-ID']", ns)
            prio_el = smv.find("scl:Address/scl:P[@type='VLAN-PRIORITY']", ns)

            dst_mac = mac_el.text.replace("-", ":") if mac_el is not None else "01:0C:CD:04:00:01"
            appid_hex = appid_el.text if appid_el is not None else "4000"
            appid = int(appid_hex, 16)
            vlan_hex = vlan_el.text if vlan_el is not None else "0C8"
            vlan_id = int(vlan_hex, 16)
            vlan_prio = int(prio_el.text) if prio_el is not None else 4

            ctrl = root.find(f".//scl:IED[@name='{ied_name}']//scl:SampledValueControl[@name='{cb_name}']", ns)
            datset = ctrl.attrib.get("datSet", "DS_SampledValues") if ctrl is not None else "DS_SampledValues"
            confrev = int(ctrl.attrib.get("confRev", "1")) if ctrl is not None else 1
            svid = ctrl.attrib.get("smvID", f"{ied_name}{ld_inst}/LLN0.{cb_name}") if ctrl is not None else ""
            smprate = int(ctrl.attrib.get("smpRate", "4000")) if ctrl is not None else 4000
            nofasdu = int(ctrl.attrib.get("nofASDU", "1")) if ctrl is not None else 1

            ds_el = root.find(f".//scl:IED[@name='{ied_name}']//scl:DataSet[@name='{datset}']", ns)
            num_channels = len(ds_el.findall("scl:FCDA", ns)) if ds_el is not None else 6

            streams.append({
                "ied": ied_name,
                "cb": cb_name,
                "ld": ld_inst,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "appid": appid,
                "vlan_id": vlan_id,
                "vlan_prio": vlan_prio,
                "svid": svid,
                "smprate": smprate,
                "nofasdu": nofasdu,
                "confrev": confrev,
                "datset": datset,
                "num_channels": num_channels,
                "scd_path": resolved_scd
            })
    return streams

AVAILABLE_SCENARIOS = {
    "normal": "Generate normal baseline Sampled Values traffic from SCD",
    "mac_mismatch": "Inject mismatched destination MAC address",
    "appid_mismatch": "Inject mismatched APPID",
    "vlan_mismatch": "Inject mismatched 802.1Q VLAN ID",
    "svid_mismatch": "Inject mismatched svID string",
    "sample_rate_anomaly": "Inject mismatched sample rate",
    "nofasdu_mismatch": "Inject mismatched nofASDU count",
    "confrev_mismatch": "Inject mismatched confRev configuration revision",
    "smpcnt_gap": "Inject smpCnt sequence gap anomaly",
    "smpcnt_duplicate": "Inject smpCnt duplicate sample count anomaly",
    "smpcnt_rollback": "Inject smpCnt sequence rollback anomaly"
}

def main():
    parser = argparse.ArgumentParser(description="IEC 61850 Sampled Values (SV) Traffic Generator & Scenario Runner")
    parser.add_argument("scenarios", nargs="*", help="Scenario name(s) to execute")
    parser.add_argument("--list", action="store_true", help="List all available SV scenarios")
    parser.add_argument("--all", action="store_true", help="Run all available SV scenarios")
    parser.add_argument("--scd", default=None, help="Path to substation.scd")
    parser.add_argument("--iface", default=None, help="Network interface name")
    parser.add_argument("--stream", type=int, default=0, help="Stream index from SCD (default: 0)")
    parser.add_argument("--count", type=int, default=5, help="Number of packets per scenario (default: 5)")
    parser.add_argument("--interval", type=float, default=0.05, help="Transmission interval in seconds")
    args = parser.parse_args()

    if args.list:
        print("Available Sampled Values (SV) Scenarios:")
        for name, desc in AVAILABLE_SCENARIOS.items():
            print(f"  {name:<25} - {desc}")
        return

    selected = []
    if args.all:
        selected = list(AVAILABLE_SCENARIOS.keys())
    elif args.scenarios:
        selected = args.scenarios
    else:
        selected = ["normal"]

    invalid = [s for s in selected if s not in AVAILABLE_SCENARIOS]
    if invalid:
        print(f"Error: Unknown scenario(s): {', '.join(invalid)}")
        print(f"Available scenarios: {', '.join(AVAILABLE_SCENARIOS.keys())}")
        sys.exit(1)

    streams = load_scd_sv_streams(args.scd)
    if not streams:
        print("No Sampled Values (SV) streams found in SCD file.")
        sys.exit(1)

    st = streams[args.stream % len(streams)]

    for sc_name in selected:
        print(f"\n[SV] Scenario: {sc_name}")
        try:
            mod = importlib.import_module(f"scenarios.{sc_name}")
            mod.run(st, args)
        except Exception as e:
            print(f"Error executing scenario '{sc_name}': {e}")
            raise

if __name__ == "__main__":
    main()
