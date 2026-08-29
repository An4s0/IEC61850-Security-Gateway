#!/usr/bin/env python3
"""
IEC 61850 MMS Traffic Generator & Scenario Runner
Entry point for running normal MMS traffic and security test scenarios from substation.scd.
Uses raw Ethernet/IP/TCP packet injection matching GOOSE and SV.
"""

import argparse
import importlib
import os
import socket
import struct
import sys
import time
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

MMS_DEFAULT_PORT = 102
MMS_ETHERTYPE = 0x0800

def inet_checksum(data: bytes) -> int:
    """Computes the standard Internet Checksum (RFC 1071)."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def ip_to_mac(ip_str: str, default_prefix: str = "00:50:56:01:00:") -> str:
    """Generates an Ethernet MAC address from an IP address string."""
    try:
        last_octet = int(ip_str.split(".")[-1])
        return f"{default_prefix}{last_octet:02X}"
    except Exception:
        return "00:50:56:01:00:01"

def build_ipv4_header(src_ip: str, dst_ip: str, payload_len: int, proto: int = 6, ident: int = 0x1234, ttl: int = 64) -> bytes:
    """Builds a standard 20-byte IPv4 header."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    total_len = 20 + payload_len
    hdr_no_chk = struct.pack(">BBHHHBBH4s4s", 0x45, 0x00, total_len, ident, 0x4000, ttl, proto, 0, src_bytes, dst_bytes)
    chk = inet_checksum(hdr_no_chk)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0x00, total_len, ident, 0x4000, ttl, proto, chk, src_bytes, dst_bytes)

def build_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, seq: int = 1000, ack: int = 0, flags: int = 0x18, window: int = 8192) -> bytes:
    """Builds a standard 20-byte TCP header with calculated checksum."""
    data_offset = 5
    offset_flags = (data_offset << 12) | flags
    tcp_hdr_no_chk = struct.pack(">HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, window, 0, 0)

    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    tcp_len = len(tcp_hdr_no_chk) + len(payload)
    pseudo = struct.pack(">4s4sBBH", src_bytes, dst_bytes, 0, 6, tcp_len)

    chk = inet_checksum(pseudo + tcp_hdr_no_chk + payload)
    return struct.pack(">HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, window, chk, 0)

def build_ethernet_frame(src_mac: str, dst_mac: str, vlan_id: int, vlan_prio: int, payload: bytes, ethertype: int = MMS_ETHERTYPE) -> bytes:
    """Constructs an Ethernet II frame with optional 802.1Q VLAN tagging."""
    dst = bytes.fromhex(dst_mac.replace(":", "").replace("-", ""))
    src = bytes.fromhex(src_mac.replace(":", "").replace("-", ""))
    if vlan_id is not None and vlan_id > 0:
        tci = ((vlan_prio & 0x7) << 13) | (vlan_id & 0x0FFF)
        hdr = dst + src + struct.pack(">HHH", 0x8100, tci, ethertype)
    else:
        hdr = dst + src + struct.pack(">H", ethertype)
    return hdr + payload

def build_mms_frame(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    payload: bytes, vlan_id=None, vlan_prio=4, seq: int = 1000, ack: int = 0, flags: int = 0x18) -> bytes:
    """Builds a complete Ethernet / IP / TCP / MMS raw frame."""
    tcp_hdr = build_tcp_header(src_ip, dst_ip, src_port, dst_port, payload, seq=seq, ack=ack, flags=flags)
    ip_hdr = build_ipv4_header(src_ip, dst_ip, len(tcp_hdr) + len(payload))
    return build_ethernet_frame(src_mac, dst_mac, vlan_id, vlan_prio, ip_hdr + tcp_hdr + payload, ethertype=MMS_ETHERTYPE)

def build_cotp_connection_request(src_tsel="0001", dst_tsel="0001") -> bytes:
    """Builds an RFC 1006 TPKT + ISO 8073 COTP Connection Request (CR) packet."""
    src_bytes = bytes.fromhex(src_tsel.replace(" ", ""))
    dst_bytes = bytes.fromhex(dst_tsel.replace(" ", ""))

    params = b""
    params += b"\xC0\x01\x0A"
    params += b"\xC1" + bytes([len(src_bytes)]) + src_bytes
    params += b"\xC2" + bytes([len(dst_bytes)]) + dst_bytes

    cotp_body = struct.pack(">BHHB", 0xE0, 0x0000, 0x0001, 0x00) + params
    li = len(cotp_body)
    cotp_pdu = bytes([li]) + cotp_body

    tpkt_len = 4 + len(cotp_pdu)
    tpkt_hdr = struct.pack(">BBH", 3, 0, tpkt_len)
    return tpkt_hdr + cotp_pdu

def build_mms_write_request(src_tsel="0001", dst_tsel="0001", invoke_id=1, var_name="XCBR1$Pos$Oper$ctlVal") -> bytes:
    """Builds an RFC 1006 TPKT + ISO 8073 COTP DT + ISO 9506 MMS Confirmed-Request-PDU (WriteRequest)."""
    var_bytes = var_name.encode("utf-8")
    mms_pdu = bytes([
        0xA0, 4 + len(var_bytes),
        0x02, 0x01, invoke_id,
        0x85, len(var_bytes),
    ]) + var_bytes

    cotp_dt = bytes([0x02, 0xF0, 0x80]) + mms_pdu
    tpkt_len = 4 + len(cotp_dt)
    tpkt_hdr = struct.pack(">BBH", 3, 0, tpkt_len)
    return tpkt_hdr + cotp_dt

_raw_socket = None

def send_frame(frame_bytes, iface=None):
    """Sends a raw Ethernet frame over the network interface without requiring a TCP connection."""
    global _raw_socket

    if hasattr(socket, "AF_PACKET"):
        try:
            if _raw_socket is None:
                _raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                if iface:
                    _raw_socket.bind((iface, 0))
            _raw_socket.send(frame_bytes)
            return True
        except Exception:
            pass

    try:
        from scapy.all import Ether, conf
        if getattr(send_frame, "_scapy_sock", None) is None:
            if iface:
                send_frame._scapy_sock = conf.L2socket(iface=iface)
            else:
                send_frame._scapy_sock = conf.L2socket()
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

def load_scd_mms_endpoints(scd_path=None):
    resolved_scd = find_scd_file(scd_path)
    if not os.path.exists(resolved_scd):
        print(f"Error: SCD file not found: {resolved_scd}")
        sys.exit(1)

    tree = ET.parse(resolved_scd)
    root = tree.getroot()
    ns = {"scl": "http://www.iec.ch/61850/2003/SCL"}

    endpoints = []
    for subnet in root.findall(".//scl:SubNetwork", ns):
        snet_name = subnet.attrib.get("name", "")
        snet_type = subnet.attrib.get("type", "")

        for ap in subnet.findall("scl:ConnectedAP", ns):
            ied_name = ap.attrib.get("iedName", "")
            ap_name = ap.attrib.get("apName", "")

            ip_el = ap.find("scl:Address/scl:P[@type='IP']", ns)
            mac_el = ap.find("scl:Address/scl:P[@type='MAC-Address']", ns)
            subnet_el = ap.find("scl:Address/scl:P[@type='IP-SUBNET']", ns)
            gateway_el = ap.find("scl:Address/scl:P[@type='IP-GATEWAY']", ns)
            psel_el = ap.find("scl:Address/scl:P[@type='OSI-PSEL']", ns)
            ssel_el = ap.find("scl:Address/scl:P[@type='OSI-SSEL']", ns)
            tsel_el = ap.find("scl:Address/scl:P[@type='OSI-TSEL']", ns)

            ip = ip_el.text if ip_el is not None else ""
            mac = mac_el.text if mac_el is not None else ip_to_mac(ip)
            mask = subnet_el.text if subnet_el is not None else "255.255.255.0"
            gw = gateway_el.text if gateway_el is not None else ""
            psel = psel_el.text if psel_el is not None else "00000001"
            ssel = ssel_el.text if ssel_el is not None else "0001"
            tsel = tsel_el.text if tsel_el is not None else "0001"

            ied_el = root.find(f".//scl:IED[@name='{ied_name}']", ns)
            has_server = (ied_el.find(f".//scl:AccessPoint[@name='{ap_name}']/scl:Server", ns) is not None) if ied_el is not None else False

            endpoints.append({
                "ied": ied_name,
                "ap": ap_name,
                "subnetwork": snet_name,
                "subnet_type": snet_type,
                "ip": ip,
                "mac": mac,
                "subnet_mask": mask,
                "gateway": gw,
                "psel": psel,
                "ssel": ssel,
                "tsel": tsel,
                "has_server": has_server,
                "scd_path": resolved_scd
            })
    return endpoints

AVAILABLE_SCENARIOS = {
    "normal": "Generate normal baseline MMS connection traffic to SCD server",
    "unknown_source": "Inject MMS connection from unconfigured source endpoint",
    "unknown_destination": "Inject MMS connection to unconfigured destination IP",
    "unexpected_endpoint": "Inject MMS connection to non-MMS interface (Process Bus)",
    "unauthorized_write": "Inject unauthorized SCADA control write / variable modification",
    "tsel_mismatch": "Inject mismatched COTP T-Selector parameter"
}

def main():
    parser = argparse.ArgumentParser(description="IEC 61850 MMS Traffic Generator & Scenario Runner")
    parser.add_argument("scenarios", nargs="*", help="Scenario name(s) to execute")
    parser.add_argument("--list", action="store_true", help="List all available MMS scenarios")
    parser.add_argument("--all", action="store_true", help="Run all available MMS scenarios")
    parser.add_argument("--scd", default=None, help="Path to substation.scd")
    parser.add_argument("--iface", default=None, help="Network interface to send frames (default: auto-detect)")
    parser.add_argument("--target-ied", default="IED1_Breaker52A", help="Target MMS Server IED name")
    parser.add_argument("--client-ied", default="IED5_StationCtrl", help="Client IED name")
    parser.add_argument("--port", type=int, default=MMS_DEFAULT_PORT, help="MMS TCP Port (default: 102)")
    parser.add_argument("--interval", type=float, default=0.05, help="Interval between frames in seconds (default: 0.05)")
    parser.add_argument("--count", type=int, default=3, help="Number of requests per scenario (default: 3)")
    args = parser.parse_args()

    if args.list:
        print("Available MMS Scenarios:")
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

    endpoints = load_scd_mms_endpoints(args.scd)
    if not endpoints:
        print("No MMS endpoints found in SCD file.")
        sys.exit(1)

    for sc_name in selected:
        print(f"\n[MMS] Scenario: {sc_name}")
        try:
            mod = importlib.import_module(f"scenarios.{sc_name}")
            mod.run(endpoints, args)
        except Exception as e:
            print(f"Error executing scenario '{sc_name}': {e}")
            raise

if __name__ == "__main__":
    main()
