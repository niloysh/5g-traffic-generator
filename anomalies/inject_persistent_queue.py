#!/usr/bin/env python3
import subprocess
import time
import json
import random
import argparse

INJECTOR_PATH = "./build/gtpu_anomaly_injector"

# Persistent queueing settings
QID_PERSISTENT_THRESHOLDS = {
    0: {"pps": 200_000, "duration_range": (1.0, 5.0)},
    1: {"pps": 1_000_000, "duration_range": (3.0, 7.0)},
    2: {"pps": 150_000, "duration_range": (2.0, 6.0)},
    3: {"pps": 800_000, "duration_range": (2.0, 6.0)},
}

# Microburst settings
QID_MICROBURST_THRESHOLDS = {
    0: {"pps": 250_000, "duration": 0.1},
    1: {"pps": 1_200_000, "duration": 0.1},
    2: {"pps": 200_000, "duration": 0.1},
    3: {"pps": 1_000_000, "duration": 0.1},
}


def group_teids_by_qid(teid_map):
    qid_groups = {qid: [] for qid in QID_PERSISTENT_THRESHOLDS.keys()}
    for teid_hex, entry in teid_map.items():
        qfi = entry["qfi"]
        if qfi == 1:
            qid = 0
        elif qfi == 2:
            qid = 1
        elif qfi == 3:
            qid = 2
        elif qfi == 5:
            qid = 3
        else:
            continue
        qid_groups[qid].append((teid_hex, entry["qfi"]))
    return qid_groups


def load_teid_map(path):
    with open(path) as f:
        return json.load(f)


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
        "--num-threads", str(num_threads),
    ]


def main(args):
    teid_map = load_teid_map(args.teid_map)
    qid_teids = group_teids_by_qid(teid_map)

    while True:
        qid = random.choice(list(QID_PERSISTENT_THRESHOLDS.keys()))
        if not qid_teids[qid]:
            continue
        teid, qfi = random.choice(qid_teids[qid])

        # Determine injection mode
        if args.mode == "mixed":
            mode = random.choice(["persistent", "microburst"])
        else:
            mode = args.mode

        # Set PPS and duration
        if mode == "persistent":
            config = QID_PERSISTENT_THRESHOLDS[qid]
            pps = config["pps"]
            duration = round(random.uniform(*config["duration_range"]), 1)
        elif mode == "microburst":
            config = QID_MICROBURST_THRESHOLDS[qid]
            pps = config["pps"]
            duration = config["duration"]
        else:
            raise ValueError(f"Unsupported mode: {mode}")

        cmd = build_command(
            teids=[teid],
            qfis=[qfi],
            pps=pps,
            duration=duration,
            num_threads=128,
            interface=args.interface,
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
        )

        print(f"\n[Injecting: {mode.upper()}] TEID={teid} (QFI={qfi}, QID={qid}) @ {pps}pps for {duration}s")
        subprocess.run(cmd)

        cooldown = random.uniform(*args.cooldown_range)
        print(f"[Cooldown] Sleeping for {cooldown:.2f} seconds...\n")
        time.sleep(cooldown)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--teid-map", type=str, required=True, help="Path to teid_mapping.json")
    parser.add_argument("--interface", type=str, default="eth2")
    parser.add_argument("--src-ip", type=str, default="192.168.44.201")
    parser.add_argument("--dst-ip", type=str, default="192.168.44.18")
    parser.add_argument("--mode", type=str, choices=["persistent", "microburst", "mixed"], default="mixed")
    parser.add_argument(
        "--cooldown-range",
        type=lambda s: tuple(map(float, s.split(","))),
        default=(5, 15),
        help="Cooldown time between injections in seconds (min,max)",
    )

    args = parser.parse_args()
    main(args)
