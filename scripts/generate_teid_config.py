#!/usr/bin/env python3

"""
generate_teid_config.py

Generates two JSON files for GTP-U traffic simulation:
- profiles.json: Contains app profiles with scaled PPS and packet size stats
- teid_map.json: Maps TEIDs to apps, with QFI/QID metadata

TEIDs are allocated proportionally using a configurable percentage per app.
"""

import json
import glob
import os
import sys
import argparse
import pandas as pd

APP_QFI_MAP = {
    "battlegrounds": 1,  # QID 0
    "geforce": 2,  # QID 1
    "zoom": 3,  # QID 2
    "teams": 3,  # QID 2
    "roblox": 5,  # QID 3
    "youtubelive": 5,  # QID 3
    "netflix": 5,  # QID 3
    "best-effort": 9,  # QID 4
}
QFI_QID_MAP = {
    1: 0,  # Highest (Battlegrounds)
    2: 1,  # High (GeForce Now)
    3: 2,  # Medium (Zoom, Teams)
    5: 3,  # Low (Roblox, streaming)
    9: 4,  # Best Effort (email, web browsing, social media)
}

TEID_SHARE_PER_APP = {
    "battlegrounds": 0.10,  # competitive gaming
    "roblox": 0.08,  # gaming
    "geforce": 0.15,  # download heavy enabled gaming
    "zoom": 0.07,  # video conferencing
    "teams": 0.07,  # video conferencing
    "youtubelive": 0.18,  # streaming
    "netflix": 0.18,  # streaming
    "best-effort": 0.17,  # email, web browsing, social media
}

parser = argparse.ArgumentParser(description="Generate TEID-to-app mapping and profiles from PCAP stats.")
parser.add_argument(
    "pcap_stats_folder",
    nargs="?",
    help="Directory containing <app>.pcap.stats.json files (ignored if --profiles is used)",
)
parser.add_argument("--total-teids", type=int, default=1000, help="Total number of TEIDs to assign (default: 1000)")
parser.add_argument("--apps", type=str, help="Comma-separated list of apps to include")
parser.add_argument("--output-dir", type=str, default=".", help="Output directory for JSON files")
parser.add_argument("--profiles", type=str, help="Use existing profiles.json (skip regeneration)")
args = parser.parse_args()

if not args.profiles and not args.pcap_stats_folder:
    print("[!] Error: Must provide either --profiles or pcap_stats_folder.")
    parser.print_help()
    sys.exit(1)

apps_filter = set(args.apps.split(",")) if args.apps else set(APP_QFI_MAP.keys())
selected_apps = [a for a in TEID_SHARE_PER_APP if a in apps_filter]

# Compute TEID counts per app
teid_counts = {app: int(args.total_teids * TEID_SHARE_PER_APP[app]) for app in selected_apps}
rounding_gap = args.total_teids - sum(teid_counts.values())
if rounding_gap > 0:
    teid_counts[selected_apps[-1]] += rounding_gap

teid_base = 0x2000
used_teids = set()
profiles = {}
teid_entries = []

# Load or generate profiles
if args.profiles:
    with open(args.profiles) as f:
        profiles = json.load(f)
    print(f"[✓] Loaded existing profiles from {args.profiles}")
else:
    for stat_file in sorted(glob.glob(os.path.join(args.pcap_stats_folder, "*.stats.json"))):
        app = os.path.basename(stat_file).replace(".pcap.stats.json", "")
        if app not in selected_apps:
            continue
        with open(stat_file) as f:
            stats = json.load(f)
        qfi = APP_QFI_MAP[app]
        qid = QFI_QID_MAP[qfi]
        profiles[app] = {"qfi": qfi, "qid": qid, "stats": stats}

    profiles_path = os.path.join(args.output_dir, "profiles.json")
    if os.path.exists(profiles_path):
        ans = input(f"[!] profiles.json already exists at {profiles_path}. Overwrite? (y/N): ")
        if ans.lower() != "y":
            print("[x] Skipping profile generation.")
        else:
            with open(profiles_path, "w") as f:
                json.dump(profiles, f, indent=2)
            print(f"[+] Wrote profiles.json to {profiles_path}")
    else:
        with open(profiles_path, "w") as f:
            json.dump(profiles, f, indent=2)
        print(f"[+] Wrote profiles.json to {profiles_path}")

# Generate TEID map
for app in selected_apps:
    count = teid_counts.get(app, 0)
    qfi = profiles[app]["qfi"]
    for _ in range(count):
        while teid_base in used_teids:
            teid_base += 1
        teid_entries.append({"teid": teid_base, "app": app, "qfi": qfi})
        used_teids.add(teid_base)
        teid_base += 1

teid_output = {
    "_meta": {
        "description": "TEID-to-app mapping based on profiles",
        "apps": selected_apps,
        "teid_share_per_app": TEID_SHARE_PER_APP,
        "qfi_qid_mapping": QFI_QID_MAP,
        "total_teids": args.total_teids,
    },
    "teids": teid_entries,
}

teid_map_path = os.path.join(args.output_dir, f"teid_map_{args.total_teids}.json")
if os.path.exists(teid_map_path):
    ans = input(f"[!] TEID map already exists at {teid_map_path}. Overwrite? (y/N): ")
    if ans.lower() != "y":
        print("[x] Skipping TEID map generation.")
        sys.exit(0)

with open(teid_map_path, "w") as f:
    json.dump(teid_output, f, indent=2)
print(f"[+] Wrote TEID map to {teid_map_path}")

# Generate per-QFI traffic summary
summary = {}
total_pps = 0.0
total_mbps = 0.0

for entry in teid_entries:
    app = entry["app"]
    qfi = entry["qfi"]
    pps = profiles[app]["stats"]["pps"]
    pkt_size = profiles[app]["stats"]["packet_size"]["avg"]

    if qfi not in summary:
        summary[qfi] = {"pps": 0.0, "mbps": 0.0}
    summary[qfi]["pps"] += pps
    summary[qfi]["mbps"] += (pps * pkt_size * 8) / 1e6

    total_pps += pps
    total_mbps += (pps * pkt_size * 8) / 1e6

df = pd.DataFrame(
    [
        {"QFI": qfi, "Expected PPS": int(data["pps"]), "Expected Mbps": round(data["mbps"], 2)}
        for qfi, data in sorted(summary.items())
    ]
)

print("\n=== Per-QFI Traffic Summary ===")
print(df.to_string(index=False))
print(f"\n[✓] Estimated total PPS: {int(total_pps):,} packets/sec")
print(f"[✓] Aggregate Mbps: {round(total_mbps, 2)} Mbps")
