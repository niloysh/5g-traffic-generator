#!/usr/bin/env python3

# This script generates GTP-U encapsulated PCAP files for different applications.
# @example: python3 scripts/generate_gtpu_pcaps.py --num-teids 20 --pcap-dir ./pcaps --out-dir ./pcaps_gtpu_20

import argparse
import subprocess
import json
from tqdm import tqdm
from pathlib import Path

# Mapping of application to QFI (matched to 4 queues in P4)
APP_QFI_MAP = {
    "battlegrounds": 1,  # qid 0: ultra-low latency (URLLC-like)
    "roblox": 1,  # qid 0: interactive control
    "geforce": 2,  # qid 1: steady, latency-bound cloud video
    "zoom": 3,  # qid 2: GBR voice/video
    "teams": 3,  # qid 2: GBR voice/video
    "youtubelive": 3,  # qid 2: GBR live streaming
    "netflix": 5,  # qid 3: streaming video/best effort
}

# Available PCAPs per app (assumed to be in --pcap-dir)
APP_PCAP_FILES = {
    "roblox": "roblox.pcap",
    "geforce": "geforce.pcap",
    "youtubelive": "youtubelive.pcap",
    "zoom": "zoom.pcap",
    "teams": "teams.pcap",
    "netflix": "netflix.pcap",
    "battlegrounds": "battlegrounds.pcap",
}


def parse_args():
    parser = argparse.ArgumentParser(description="Generate TEID-tagged GTP-U PCAPs per app profile.")
    parser.add_argument("--num-teids", type=int, required=True, help="Number of TEIDs to generate")
    parser.add_argument("--pcap-dir", type=Path, default=Path("./pcaps"), help="Directory containing source app pcaps")
    parser.add_argument("--out-dir", type=Path, default=Path("./encapsulated"), help="Where to save GTP-U pcaps")
    parser.add_argument(
        "--encapsulator", type=Path, default=Path("./build/gtpu_encapsulator"), help="Path to gtpu_encapsulator binary"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    mapping = {}

    apps = list(APP_QFI_MAP.keys())
    for i in tqdm(range(args.num_teids), desc="Encapsulating PCAPs"):
        teid = 0x2000 + i
        app = apps[i % len(apps)]
        qfi = APP_QFI_MAP[app]
        src_pcap = args.pcap_dir / APP_PCAP_FILES[app]
        out_pcap = args.out_dir / f"teid_0x{teid:04x}_{app}_qfi{qfi}.pcap"

        cmd = [
            "sudo",
            str(args.encapsulator),
            str(src_pcap),
            str(out_pcap),
            "--teid",
            f"0x{teid:04x}",
            "--qfi",
            str(qfi),
        ]

        print(f"[+] Generating {out_pcap.name} for TEID=0x{teid:04x}, QFI={qfi}, App={app}")
        subprocess.run(cmd, check=True)

        mapping[f"0x{teid:04x}"] = {"app": app, "qfi": qfi, "pcap": str(out_pcap.name)}

    with open(args.out_dir / "teid_mapping.json", "w") as f:
        json.dump(mapping, f, indent=2)
    print(f"[✓] Wrote mapping to {args.out_dir / 'teid_mapping.json'}")


if __name__ == "__main__":
    main()
