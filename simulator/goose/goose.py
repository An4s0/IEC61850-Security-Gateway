#!/usr/bin/env python3
"""
IEC 61850 GOOSE Traffic Generator & Scenario Runner
Entry point for running normal GOOSE traffic and security test scenarios from substation.scd.
"""

import argparse
import importlib
import os
import struct
import sys
import time
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

GOOSE_ETHERTYPE = 0x88B8

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

def ber_bool(tag: int, val: bool) -> bytes:
    return ber_tlv(tag, b"\xFF" if val else b"\x00")

def ber_int(tag: int, val: int) -> bytes:
    if val == 0:
        return ber_tlv(tag, b"\x00")
    length = (val.bit_length() + 8) // 8
    b = val.to_bytes(length, "big", signed=True)
    return ber_tlv(tag, b)

def ber_str(tag: int, val: str) -> bytes:
    return ber_tlv(tag, val.encode("utf-8"))

def ber_utctime(tag: int, epoch_seconds: float) -> bytes:
    sec = int(epoch_seconds)
    frac = int((epoch_seconds - sec) * 0xFFFFFF) & 0xFFFFFF
    val = struct.pack(">I", sec) + frac.to_bytes(3, "big") + b"\x0A"
    return ber_tlv(tag, val)

def encode_bool_data(val: bool) -> bytes:
    return ber_bool(0x83, val)

def build_all_data(values):
    items = b"".join(encode_bool_data(v) for v in values)
    return ber_tlv(0xAB, items)

def build_goose_pdu(gocbref, time_allowed, datset, goid, t, stnum, sqnum,
                    test, confrev, ndscom, values):
    body = b""
    body += ber_str(0x80, gocbref)
    body += ber_int(0x81, time_allowed)
    body += ber_str(0x82, datset)
    body += ber_str(0x83, goid)
    body += ber_utctime(0x84, t)
    body += ber_int(0x85, stnum)
    body += ber_int(0x86, sqnum)
    body += ber_bool(0x87, test)
    body += ber_int(0x88, confrev)
    body += ber_bool(0x89, ndscom)
    body += ber_int(0x8A, len(values))
    body += build_all_data(values)
    return ber_tlv(0x61, body)

def build_goose_apdu(appid, pdu_bytes):
    length = 8 + len(pdu_bytes)
    header = struct.pack(">HHHH", appid, length, 0x0000, 0x0000)
    return header + pdu_bytes

def build_ethernet_frame(src_mac, dst_mac, vlan_id, vlan_prio, payload):
    dst = bytes.fromhex(dst_mac.replace(":", "").replace("-", ""))
    src = bytes.fromhex(src_mac.replace(":", "").replace("-", ""))
    if vlan_id is not None and vlan_id > 0:
        tci = ((vlan_prio & 0x7) << 13) | (vlan_id & 0x0FFF)
        hdr = dst + src + struct.pack(">HHH", 0x8100, tci, GOOSE_ETHERTYPE)
    else:
        hdr = dst + src + struct.pack(">H", GOOSE_ETHERTYPE)
    return hdr + payload

_raw_socket = None

def send_frame(frame_bytes, iface=None):
    global _raw_socket
    import socket
    
    if hasattr(socket, "AF_PACKET"):
        try:
            if _raw_socket is None:
                _raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                _raw_socket.bind((iface or "eth0", 0))
            _raw_socket.send(frame_bytes)
            return True
        except Exception:
            pass

    try:
        from scapy.all import Ether, conf
        if getattr(send_frame, "_scapy_sock", None) is None:
            send_frame._scapy_sock = conf.L2socket(iface=iface or "eth0")
        eth = Ether(frame_bytes)
        send_frame._scapy_sock.send(eth)
        return True
    except ImportError:
        pass
    except Exception:
        pass
        
    return False

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

def load_scd_goose_streams(scd_path=None):
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
        src_mac = src_mac_el.text.replace("-", ":") if src_mac_el is not None else "00:30:A7:01:00:01"

        for gse in ap.findall("scl:GSE", ns):
            cb_name = gse.attrib.get("cbName", "")
            ld_inst = gse.attrib.get("ldInst", "")

            mac_el = gse.find("scl:Address/scl:P[@type='MAC-Address']", ns)
            appid_el = gse.find("scl:Address/scl:P[@type='APPID']", ns)
            vlan_el = gse.find("scl:Address/scl:P[@type='VLAN-ID']", ns)
            prio_el = gse.find("scl:Address/scl:P[@type='VLAN-PRIORITY']", ns)
            min_t_el = gse.find("scl:MinTime", ns)
            max_t_el = gse.find("scl:MaxTime", ns)

            dst_mac = mac_el.text.replace("-", ":") if mac_el is not None else "01:0C:CD:01:00:01"
            appid_hex = appid_el.text if appid_el is not None else "0001"
            appid = int(appid_hex, 16)
            vlan_hex = vlan_el.text if vlan_el is not None else "064"
            vlan_id = int(vlan_hex, 16)
            vlan_prio = int(prio_el.text) if prio_el is not None else 4
            min_time = int(min_t_el.text) if min_t_el is not None else 4
            max_time = int(max_t_el.text) if max_t_el is not None else 1000

            ctrl = root.find(f".//scl:IED[@name='{ied_name}']//scl:GSEControl[@name='{cb_name}']", ns)
            datset = ctrl.attrib.get("datSet", "DS_Default") if ctrl is not None else "DS_Default"
            confrev = int(ctrl.attrib.get("confRev", "1")) if ctrl is not None else 1
            goid = ctrl.attrib.get("appID", f"{ied_name}{ld_inst}/LLN0.{cb_name}") if ctrl is not None else ""
            gocbref = f"{ied_name}{ld_inst}/LLN0$GO${cb_name}"

            ds_el = root.find(f".//scl:IED[@name='{ied_name}']//scl:DataSet[@name='{datset}']", ns)
            num_entries = len(ds_el.findall("scl:FCDA", ns)) if ds_el is not None else 4

            streams.append({
                "ied": ied_name,
                "cb": cb_name,
                "ld": ld_inst,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "appid": appid,
                "vlan_id": vlan_id,
                "vlan_prio": vlan_prio,
                "min_time_ms": min_time,
                "max_time_ms": max_time,
                "gocbref": gocbref,
                "datset": f"{ied_name}{ld_inst}/LLN0${datset}",
                "goid": goid,
                "confrev": confrev,
                "num_entries": num_entries,
                "scd_path": resolved_scd
            })
    return streams

AVAILABLE_SCENARIOS = {
    "normal": "Generate normal baseline GOOSE traffic from SCD",
    "mac_mismatch": "Inject mismatched destination MAC address",
    "appid_mismatch": "Inject mismatched APPID",
    "vlan_mismatch": "Inject mismatched 802.1Q VLAN ID",
    "vlan_priority_mismatch": "Inject mismatched 802.1Q VLAN Priority",
    "confrev_mismatch": "Inject mismatched confRev configuration revision",
    "timing_fast": "Inject abnormally fast burst traffic",
    "timing_slow": "Inject abnormally slow heartbeat traffic (miss timeAllowedtoLive)"
}

def main():
    parser = argparse.ArgumentParser(description="IEC 61850 GOOSE Traffic Generator & Scenario Runner")
    parser.add_argument("scenarios", nargs="*", help="Scenario name(s) to execute")
    parser.add_argument("--list", action="store_true", help="List all available GOOSE scenarios")
    parser.add_argument("--all", action="store_true", help="Run all available GOOSE scenarios")
    parser.add_argument("--scd", default=None, help="Path to substation.scd")
    parser.add_argument("--iface", default=None, help="Network interface name")
    parser.add_argument("--stream", type=int, default=0, help="Stream index from SCD (default: 0)")
    parser.add_argument("--count", type=int, default=5, help="Number of packets per scenario (default: 5)")
    parser.add_argument("--interval", type=float, default=None, help="Fixed interval in seconds")
    args = parser.parse_args()

    if args.list:
        print("Available GOOSE Scenarios:")
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

    streams = load_scd_goose_streams(args.scd)
    if not streams:
        print("No GOOSE streams found in SCD file.")
        sys.exit(1)

    st = streams[args.stream % len(streams)]
    results = {}

    for sc_name in selected:
        print(f"\n{'='*60}")
        print(f"  Scenario: {sc_name}")
        print(f"{'='*60}")
        try:
            mod = importlib.import_module(f"scenarios.{sc_name}")
            mod.run(st, args)
            results[sc_name] = "OK"
        except Exception as e:
            print(f"Error executing scenario '{sc_name}': {e}")
            results[sc_name] = f"FAIL ({e})"

    if len(selected) > 1:
        print(f"\n{'='*60}")
        print("  GOOSE IDS Test Summary")
        print(f"{'='*60}")
        for name, status in results.items():
            print(f"  {name:<30} {status}")
        print(f"{'='*60}\n")

if __name__ == "__main__":
    main()

