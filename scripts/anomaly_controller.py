#!/usr/bin/env python3
import subprocess
import signal
import random
import time
import json
import argparse
from pathlib import Path

# Global config
INJECTOR_PATH = "./build/gtpu_anomaly_injector"
DEFAULT_INTERFACE = "enp2s0f0"
DEFAULT_SRC_IP = "192.168.44.13"
DEFAULT_DST_IP = "192.168.44.18"

def load_teid_mapping(json_path):
    with open(json_path) as f:
        raw = json.load(f)
    return {k.lower(): v for k, v in raw.items()}

def build_command(teids, qfis, pps, duration, num_threads, interface, src_ip, dst_ip):
    return [
        "sudo", INJECTOR_PATH,
        "--interface", interface,
        "--src-ip", src_ip,
        "--dst-ip", dst_ip,
        "--teids", ",".join(teids),
        "--qfis", ",".join(str(q) for q in qfis),
        "--pps", str(pps),
        "--duration", str(duration),
        "--num-threads", str(num_threads)
    ]

def main():
    parser = argparse.ArgumentParser(description="Randomized anomaly injection controller.")
    parser.add_argument("--teid-map", required=True, help="Path to teid_mapping.json")
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--src-ip", default=DEFAULT_SRC_IP)
    parser.add_argument("--dst-ip", default=DEFAULT_DST_IP)
    parser.add_argument("--min-teids", type=int, default=1)
    parser.add_argument("--max-teids", type=int, default=4)
    parser.add_argument("--min-pps", type=int, default=200000)
    parser.add_argument("--max-pps", type=int, default=600000)
    parser.add_argument("--min-duration", type=float, default=1.0)
    parser.add_argument("--max-duration", type=float, default=5.0)
    parser.add_argument("--sleep-range", type=float, nargs=2, default=[2.0, 6.0])
    parser.add_argument("--max-anomalies", type=int, default=None)
    args = parser.parse_args()

    teid_map = load_teid_mapping(args.teid_map)
    all_teids = list(teid_map.keys())

    def handle_sigint(sig, frame):
        print("\n[!] Ctrl+C received, exiting...")
        exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    count = 0
    while args.max_anomalies is None or count < args.max_anomalies:
        n = random.randint(args.min_teids, args.max_teids)
        selected_teids = random.sample(all_teids, k=n)
        selected_qfis = [teid_map[tid] for tid in selected_teids]
        duration = round(random.uniform(args.min_duration, args.max_duration), 2)
        pps = random.randint(args.min_pps, args.max_pps)
        sleep_time = random.uniform(*args.sleep_range)

        cmd = build_command(
            teids=selected_teids,
            qfis=selected_qfis,
            pps=pps,
            duration=duration,
            num_threads=n,
            interface=args.interface,
            src_ip=args.src_ip,
            dst_ip=args.dst_ip
        )

        print(f"[{count+1}] Injecting anomaly: TEIDs={selected_teids}, QFIs={selected_qfis}, "
              f"PPS={pps}, duration={duration}s, threads={n}")
        subprocess.run(cmd)
        time.sleep(sleep_time)
        count += 1

if __name__ == "__main__":
    main()
