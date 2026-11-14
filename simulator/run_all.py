#!/usr/bin/env python3
"""
IEC 61850 Unified Multi-Protocol Simulator & Scenario Runner
============================================================
Executes GOOSE, Sampled Values (SV / IEC 61850-9-2LE), and MMS (IEC 61850-8-1 / ISO 9506)
scenarios in a randomized order across all protocols.

Usage:
  python simulator/run_all.py
  python simulator/run_all.py --seed 1234
  python simulator/run_all.py --count 3
  python simulator/run_all.py --list

Stress mode (continuous high-rate traffic, independent of scenarios):
  python simulator/run_all.py --stress --rate 5000 --duration 30
  python simulator/run_all.py --stress --rate 2000 --duration 10 --protocols GOOSE,SV
  python simulator/run_all.py --stress --rate 10000 --duration 60 --iface eth0
"""

import argparse
import importlib.util
import os
import random
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

# Add protocol package directories to sys.path
GOOSE_DIR = os.path.join(SCRIPT_DIR, "goose")
SV_DIR = os.path.join(SCRIPT_DIR, "sv")
MMS_DIR = os.path.join(SCRIPT_DIR, "mms")

for d in [GOOSE_DIR, SV_DIR, MMS_DIR, SCRIPT_DIR]:
    if d not in sys.path:
        sys.path.insert(0, d)

import goose as goose_mod
import sv as sv_mod
import mms as mms_mod

class ScenarioArgs:
    """Configurable arguments passed to each scenario run() function."""
    def __init__(self, count=3, interval=None, iface=None, stream=0,
                 target_ied="IED1_Breaker52A", client_ied="IED5_StationCtrl",
                 port=102, scd=None):
        self.count = count
        self.interval = interval
        self.iface = iface
        self.stream = stream
        self.target_ied = target_ied
        self.client_ied = client_ied
        self.port = port
        self.scd = scd

def find_scd_file(specified_path=None):
    """Locate the Substation Configuration Description (SCD) file."""
    candidates = []
    if specified_path:
        candidates.append(specified_path)
    candidates.extend([
        os.path.join(SCRIPT_DIR, "substation.scd"),
        os.path.join(PROJECT_ROOT, "substation.scd"),
        "substation.scd",
        "simulator/substation.scd",
    ])
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    return os.path.abspath(os.path.join(SCRIPT_DIR, "substation.scd"))

def load_scenario_module(proto_dir, scenario_name):
    """Dynamically load scenario module from scenarios/<name>.py."""
    scenario_path = os.path.join(proto_dir, "scenarios", f"{scenario_name}.py")
    if not os.path.exists(scenario_path):
        raise FileNotFoundError(f"Scenario script not found: {scenario_path}")
    
    spec = importlib.util.spec_from_file_location(f"{os.path.basename(proto_dir)}_{scenario_name}", scenario_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def build_scenario_pool(active_protocols, scd_path):
    """Build the unified list of all (Protocol, Scenario, RunnerFn, ContextObj) items."""
    pool = []
    protos = [p.upper() for p in active_protocols]

    if "GOOSE" in protos:
        goose_streams = goose_mod.load_scd_goose_streams(scd_path)
        if not goose_streams:
            raise RuntimeError("No GOOSE streams found in SCD.")
        for sc_name in goose_mod.AVAILABLE_SCENARIOS:
            pool.append(("GOOSE", sc_name, GOOSE_DIR, goose_streams))

    if "SV" in protos:
        sv_streams = sv_mod.load_scd_sv_streams(scd_path)
        if not sv_streams:
            raise RuntimeError("No SV streams found in SCD.")
        for sc_name in sv_mod.AVAILABLE_SCENARIOS:
            pool.append(("SV", sc_name, SV_DIR, sv_streams))

    if "MMS" in protos:
        mms_endpoints = mms_mod.load_scd_mms_endpoints(scd_path)
        if not mms_endpoints:
            raise RuntimeError("No MMS endpoints found in SCD.")
        for sc_name in mms_mod.AVAILABLE_SCENARIOS:
            pool.append(("MMS", sc_name, MMS_DIR, mms_endpoints))

    return pool

def print_banner(seed, count, total, scd_path, protocols):
    print("=" * 80, flush=True)
    print("        IEC 61850 UNIFIED MULTI-PROTOCOL SECURITY SIMULATOR", flush=True)
    print(f"        Protocols: {', '.join(protocols)}", flush=True)
    print("=" * 80, flush=True)
    print(f"  Configuration SCD : {scd_path}", flush=True)
    print(f"  Total Scenarios   : {total}", flush=True)
    print(f"  Packets/Scenario  : {count}", flush=True)
    print(f"  Randomization Seed: {seed} (Use '--seed {seed}' to reproduce this exact sequence)", flush=True)
    print("=" * 80, flush=True)
    print(flush=True)

def print_summary(results, seed, total_duration):
    total = len(results)
    passed_count = sum(1 for r in results if r["passed"])
    failed_count = total - passed_count

    print(flush=True)
    print("=" * 80, flush=True)
    print("                     IEC 61850 SIMULATION SUMMARY", flush=True)
    print("=" * 80, flush=True)
    print(f"  Execution Order & Results (Seed: {seed}):", flush=True)
    print(f"  {'#':<4} {'Protocol':<10} {'Scenario Name':<28} {'Status':<10} {'Duration':<10} {'Details'}", flush=True)
    print("  " + "-" * 76, flush=True)

    for idx, r in enumerate(results, 1):
        status_str = "PASS" if r["passed"] else "FAIL"
        details = "" if r["passed"] else f"Error: {r['error']}"
        print(f"  {idx:<4} {r['protocol']:<10} {r['scenario']:<28} {status_str:<10} {r['duration']:.2f}s     {details}", flush=True)

    print("  " + "-" * 76, flush=True)
    print(f"  Total: {total} | Passed: {passed_count} | Failed: {failed_count} | Total Duration: {total_duration:.2f}s", flush=True)
    if failed_count == 0:
        print("  Overall Status: ALL SCENARIOS PASSED SUCCESSFULLY", flush=True)
    else:
        print(f"  Overall Status: {failed_count} SCENARIO(S) FAILED", flush=True)
    print("=" * 80, flush=True)
    print(flush=True)

def build_stress_generators(protocols, scd_path, stream_index, target_ied, client_ied, port):
    """Build one frame generator and sender per requested protocol.

    Kept separate from the scenario machinery: stress mode never loads a
    scenario module and never touches the scenario pool.
    """
    generators = []

    if "GOOSE" in protocols:
        streams = goose_mod.load_scd_goose_streams(scd_path)
        if not streams:
            raise RuntimeError("No GOOSE streams found in SCD.")
        stream = streams[stream_index % len(streams)]
        state = {"sqnum": 0}
        stnum = stream.get("stnum", 0) + 1
        values = [False] * stream["num_entries"]
        time_allowed = stream["max_time_ms"] * 2

        def make_goose(_st=stream, _state=state, _values=values, _tal=time_allowed, _stnum=stnum):
            pdu = goose_mod.build_goose_pdu(
                gocbref=_st["gocbref"],
                time_allowed=_tal,
                datset=_st["datset"],
                goid=_st["goid"],
                t=time.time(),
                stnum=_stnum,
                sqnum=_state["sqnum"],
                test=False,
                confrev=_st["confrev"],
                ndscom=False,
                values=_values,
            )
            apdu = goose_mod.build_goose_apdu(_st["appid"], pdu)
            _state["sqnum"] = (_state["sqnum"] + 1) & 0xFFFFFFFF
            return goose_mod.build_ethernet_frame(
                _st["src_mac"], _st["dst_mac"], _st["vlan_id"], _st["vlan_prio"], apdu
            )

        generators.append(("GOOSE", make_goose, goose_mod.send_frame))

    if "SV" in protocols:
        streams = sv_mod.load_scd_sv_streams(scd_path)
        if not streams:
            raise RuntimeError("No SV streams found in SCD.")
        stream = streams[stream_index % len(streams)]
        state = {"smpcnt": 0}
        wrap = stream["smprate"] if stream["smprate"] > 0 else 4000

        def make_sv(_st=stream, _state=state, _wrap=wrap):
            samples = sv_mod.generate_3phase_samples(
                _state["smpcnt"], sample_rate=_st["smprate"], num_channels=_st["num_channels"]
            )
            pdu = sv_mod.build_sv_pdu(
                svid=_st["svid"],
                smpcnt=_state["smpcnt"],
                confrev=_st["confrev"],
                smprate=_st["smprate"],
                samples=samples,
                nofasdu=_st["nofasdu"],
                smpsynch=2,
            )
            apdu = sv_mod.build_sv_apdu(_st["appid"], pdu)
            _state["smpcnt"] = (_state["smpcnt"] + 1) % _wrap
            return sv_mod.build_ethernet_frame(
                _st["src_mac"], _st["dst_mac"], _st["vlan_id"], _st["vlan_prio"], apdu
            )

        generators.append(("SV", make_sv, sv_mod.send_frame))

    if "MMS" in protocols:
        endpoints = mms_mod.load_scd_mms_endpoints(scd_path)
        if not endpoints:
            raise RuntimeError("No MMS endpoints found in SCD.")
        server_ep = next(
            (ep for ep in endpoints if ep["ied"] == target_ied and ep.get("has_server")), None
        ) or endpoints[0]
        client_ep = next((ep for ep in endpoints if ep["ied"] == client_ied), None) or endpoints[-1]

        payload = mms_mod.build_cotp_connection_request(
            src_tsel=client_ep["tsel"], dst_tsel=server_ep["tsel"]
        )
        frame = mms_mod.build_mms_frame(
            src_mac=client_ep.get("mac", "00:50:56:01:00:15"),
            dst_mac=server_ep.get("mac", "00:50:56:01:00:11"),
            src_ip=client_ep["ip"],
            dst_ip=server_ep["ip"],
            src_port=49152,
            dst_port=port,
            payload=payload,
        )

        generators.append(("MMS", lambda _f=frame: _f, mms_mod.send_frame))

    return generators


def run_stress(args, scd_path, protocols):
    """Continuously inject GOOSE/SV/MMS frames at a configurable rate and report statistics."""
    try:
        generators = build_stress_generators(
            protocols, scd_path, args.stream, args.target_ied, args.client_ied, args.port
        )
    except RuntimeError as ex:
        print(f"Error: {ex}", file=sys.stderr, flush=True)
        return 1

    if not generators:
        print("Error: no protocols selected for stress mode.", file=sys.stderr, flush=True)
        return 1

    rate = args.rate
    duration = args.duration
    interval = 1.0 / rate

    stats = {name: {"attempted": 0, "sent": 0, "errors": 0, "bytes": 0} for name, _, _ in generators}

    print("=" * 80, flush=True)
    print("        IEC 61850 STRESS TEST - CONTINUOUS TRAFFIC INJECTION", flush=True)
    print("=" * 80, flush=True)
    print(f"  Configuration SCD : {scd_path}", flush=True)
    print(f"  Protocols         : {', '.join(name for name, _, _ in generators)}", flush=True)
    print(f"  Target rate       : {rate:.0f} packets/s", flush=True)
    print(f"  Duration          : {duration:.2f} s", flush=True)
    print(f"  Interface         : {args.iface or 'auto'}", flush=True)
    print("=" * 80, flush=True)
    print("  Running... (Ctrl+C to stop early)", flush=True)
    print(flush=True)

    send_failures_seen = False
    warned_unavailable = False
    pacing_slips = 0
    idx = 0

    # Warm up each sender outside the timed window: the first call can pay a
    # one-off cost (socket setup, or a failed scapy import attempt) that would
    # otherwise consume the whole duration and skew the throughput figures.
    for _name, _make_frame, _send in generators:
        if not _send(_make_frame(), iface=args.iface):
            send_failures_seen = True
            if not warned_unavailable:
                warned_unavailable = True
                print(
                    "  [!] Frame transmission unavailable on this host "
                    "(needs AF_PACKET/root or scapy). Counting as errors.",
                    flush=True,
                )

    next_t = time.perf_counter()
    start = next_t
    interrupted = False

    try:
        while True:
            elapsed = time.perf_counter() - start
            if duration > 0 and elapsed >= duration:
                break

            name, make_frame, send = generators[idx % len(generators)]
            idx += 1
            entry = stats[name]
            entry["attempted"] += 1

            frame = make_frame()
            if send(frame, iface=args.iface):
                entry["sent"] += 1
                entry["bytes"] += len(frame)
            else:
                entry["errors"] += 1
                send_failures_seen = True
                if not warned_unavailable:
                    warned_unavailable = True
                    print(
                        "  [!] Frame transmission unavailable on this host "
                        "(needs AF_PACKET/root or scapy). Counting as errors.",
                        flush=True,
                    )

            next_t += interval
            now = time.perf_counter()
            if now < next_t:
                time.sleep(next_t - now)
            elif now - next_t > interval:
                pacing_slips += 1
                next_t = now
    except KeyboardInterrupt:
        interrupted = True

    elapsed = time.perf_counter() - start

    total_attempted = sum(s["attempted"] for s in stats.values())
    total_sent = sum(s["sent"] for s in stats.values())
    total_errors = sum(s["errors"] for s in stats.values())
    total_bytes = sum(s["bytes"] for s in stats.values())

    print(flush=True)
    print("=" * 80, flush=True)
    print("                        STRESS TEST SUMMARY", flush=True)
    print("=" * 80, flush=True)
    if interrupted:
        print("  Stopped early by user", flush=True)
        print(flush=True)

    def sent_of(name):
        return stats[name]["sent"] if name in stats else 0

    def failed_of(name):
        return stats[name]["errors"] if name in stats else 0

    print(f"  FRAMES SENT  (total: {total_sent:,})", flush=True)
    for name in ("GOOSE", "SV", "MMS"):
        print(f"    {name:<8} ......................... {sent_of(name):>10,}", flush=True)
    print("  " + "-" * 76, flush=True)
    print(f"    {'TOTAL':<8} ......................... {total_sent:>10,}", flush=True)
    print(flush=True)

    print(f"  FAILED TRANSMISSIONS  (total: {total_errors:,})", flush=True)
    for name in ("GOOSE", "SV", "MMS"):
        print(f"    {name:<8} ......................... {failed_of(name):>10,}", flush=True)
    print("  " + "-" * 76, flush=True)
    print(f"    {'TOTAL':<8} ......................... {total_errors:>10,}", flush=True)
    print(flush=True)

    avg_frame = (total_bytes / total_sent) if total_sent else 0.0
    print("  " + "-" * 76, flush=True)
    print(f"  Frames attempted  : {total_attempted:,}", flush=True)
    print(f"  Bytes sent        : {total_bytes:,}", flush=True)
    print(f"  Average frame size: {avg_frame:.0f} B", flush=True)
    print(f"  Elapsed time      : {elapsed:.2f} s", flush=True)
    if elapsed > 0:
        print(f"  Send throughput   : {total_sent / elapsed:,.0f} frames/s "
              f"({total_bytes * 8 / elapsed / 1e6:.2f} Mbit/s)", flush=True)
        print(f"  Attempt throughput: {total_attempted / elapsed:,.0f} frames/s", flush=True)
        achieved = (total_sent / elapsed) if total_sent else (total_attempted / elapsed)
        print(f"  Rate achievement  : {achieved / rate * 100:.1f}% of {rate:.0f} frames/s", flush=True)
    print(f"  Pacing slips      : {pacing_slips}", flush=True)
    if send_failures_seen and total_sent == 0:
        print("  Note: no frame reached the wire on this host (see warning above).", flush=True)
    print("=" * 80, flush=True)

    return 0 if total_errors == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description="Unified IEC 61850 Multi-Protocol Scenario Runner (GOOSE, SV, MMS)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible execution order (e.g. --seed 1234)"
    )
    parser.add_argument(
        "--scd",
        default=None,
        help="Path to substation.scd configuration description file"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=3,
        help="Number of packets/requests per scenario (default: 3)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Transmission interval in seconds (default: scenario/protocol default)"
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Network interface name (optional, auto-detected if omitted)"
    )
    parser.add_argument(
        "--protocols",
        default="GOOSE,SV,MMS",
        help="Comma-separated list of protocols to include (default: GOOSE,SV,MMS)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available scenarios across all protocols"
    )
    parser.add_argument(
        "--stream",
        type=int,
        default=0,
        help="Stream index from SCD (default: 0)"
    )
    parser.add_argument(
        "--target-ied",
        default="IED1_Breaker52A",
        help="Target MMS Server IED name (default: IED1_Breaker52A)"
    )
    parser.add_argument(
        "--client-ied",
        default="IED5_StationCtrl",
        help="Client MMS IED name (default: IED5_StationCtrl)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=102,
        help="MMS TCP Port (default: 102)"
    )
    parser.add_argument(
        "--stress",
        action="store_true",
        help="Stress mode: continuously inject GOOSE/SV/MMS traffic at a fixed rate "
             "(independent of the scenario runner)"
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=1000.0,
        help="Stress mode: target packets per second across all protocols (default: 1000)"
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Stress mode: run duration in seconds, 0 = until interrupted (default: 10)"
    )
    args = parser.parse_args()

    scd_path = find_scd_file(args.scd)
    if not os.path.exists(scd_path):
        print(f"Error: SCD file not found: {scd_path}", file=sys.stderr, flush=True)
        return 1

    active_protocols = [p.strip().upper() for p in args.protocols.split(",") if p.strip()]

    if args.list:
        print("Available IEC 61850 Multi-Protocol Scenarios:", flush=True)
        if "GOOSE" in active_protocols:
            print(f"\n  [GOOSE] ({len(goose_mod.AVAILABLE_SCENARIOS)} scenarios):", flush=True)
            for sc, desc in goose_mod.AVAILABLE_SCENARIOS.items():
                print(f"    - {sc:<25} : {desc}", flush=True)
        if "SV" in active_protocols:
            print(f"\n  [SV] ({len(sv_mod.AVAILABLE_SCENARIOS)} scenarios):", flush=True)
            for sc, desc in sv_mod.AVAILABLE_SCENARIOS.items():
                print(f"    - {sc:<25} : {desc}", flush=True)
        if "MMS" in active_protocols:
            print(f"\n  [MMS] ({len(mms_mod.AVAILABLE_SCENARIOS)} scenarios):", flush=True)
            for sc, desc in mms_mod.AVAILABLE_SCENARIOS.items():
                print(f"    - {sc:<25} : {desc}", flush=True)
        total_scs = sum(len(m.AVAILABLE_SCENARIOS) for m, p in [(goose_mod, "GOOSE"), (sv_mod, "SV"), (mms_mod, "MMS")] if p in active_protocols)
        print(f"\nTotal: {total_scs} scenarios across {len(active_protocols)} protocol(s)\n", flush=True)
        return 0

    if args.stress:
        if args.rate <= 0:
            print("Error: --rate must be greater than 0.", file=sys.stderr, flush=True)
            return 1
        if args.duration < 0:
            print("Error: --duration must be 0 or greater.", file=sys.stderr, flush=True)
            return 1
        return run_stress(args, scd_path, active_protocols)

    pool = build_scenario_pool(active_protocols, scd_path)
    if not pool:
        print(f"Error: No scenarios found for selected protocols: {args.protocols}", file=sys.stderr, flush=True)
        return 1

    # Determine random seed
    seed = args.seed if args.seed is not None else random.randint(100000, 999999)
    rng = random.Random(seed)

    # Completely shuffle the pool of scenarios across all protocols
    shuffled_pool = list(pool)
    rng.shuffle(shuffled_pool)

    print_banner(seed, args.count, len(shuffled_pool), scd_path, active_protocols)

    results = []
    overall_start = time.time()

    for idx, (protocol, scenario, proto_dir, context_data) in enumerate(shuffled_pool, 1):
        print(f"\n{'='*70}", flush=True)
        print(f"  [{idx:>2}/{len(shuffled_pool)}] PROTOCOL: [{protocol}] | SCENARIO: {scenario}", flush=True)
        print(f"{'='*70}", flush=True)

        t0 = time.time()
        passed = False
        err_msg = ""

        try:
            mod = load_scenario_module(proto_dir, scenario)
            
            # Prepare protocol-specific arguments with sensible interval defaults
            proto_interval = args.interval
            if proto_interval is None:
                proto_interval = 0.05 if protocol in ["SV", "MMS"] else None

            scenario_args = ScenarioArgs(
                count=args.count,
                interval=proto_interval,
                iface=args.iface,
                stream=args.stream,
                target_ied=args.target_ied,
                client_ied=args.client_ied,
                port=args.port,
                scd=scd_path
            )

            # Pass context object (single stream for GOOSE/SV, full endpoints list for MMS)
            if protocol in ["GOOSE", "SV"]:
                selected_stream = context_data[args.stream % len(context_data)]
                if protocol == "GOOSE":
                    selected_stream["stnum"] = selected_stream.get("stnum", 0) + 1
                mod.run(selected_stream, scenario_args)
            elif protocol == "MMS":
                mod.run(context_data, scenario_args)

            passed = True
            time.sleep(0.15)
        except Exception as ex:
            passed = False
            err_msg = str(ex)
            print(f"\n  [!] Error in {protocol} scenario '{scenario}': {ex}", flush=True)

        duration = time.time() - t0
        status_text = "PASS" if passed else f"FAIL ({err_msg})"
        print(f"\n  --> [{protocol}] Scenario '{scenario}' Result: {status_text} (took {duration:.2f}s)", flush=True)

        results.append({
            "protocol": protocol,
            "scenario": scenario,
            "passed": passed,
            "duration": duration,
            "error": err_msg
        })

    total_duration = time.time() - overall_start
    print_summary(results, seed, total_duration)

    # Return non-zero exit code if any scenario failed
    has_failures = any(not r["passed"] for r in results)
    return 1 if has_failures else 0

if __name__ == "__main__":
    sys.exit(main())
