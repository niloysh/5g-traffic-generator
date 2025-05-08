#!/usr/bin/env python3
"""
generate_teid_map.py

Generates two JSON files for GTP-U traffic simulation:
- profiles.json: Contains app profiles with scaled PPS and packet size stats
- teid_map.json: Maps TEIDs to apps, with QFI/QID metadata

TEIDs are allocated proportionally using a configurable percentage per app.
We can control the total number of TEIDs and optionally scale all PPS values.

Usage:
  python generate_teid_map.py <pcap_stats_folder> [--total-teids 1000]
                              [--apps app1,app2,...]
                              [--scale-pps 0.5]
                              [--output-prefix ./output/]
"""

import json
import glob
import os
import sys
import argparse

APP_QFI_MAP = {"battlegrounds": 1, "roblox": 1, "geforce": 2, "zoom": 3, "teams": 3, "youtubelive": 3, "netflix": 5}
QFI_QID_MAP = {1: 0, 2: 1, 3: 2, 5: 3}

TEID_SHARE_PER_APP = {
    "battlegrounds": 0.10,
    "roblox": 0.10,
    "geforce": 0.10,
    "zoom": 0.15,
    "teams": 0.15,
    "youtubelive": 0.20,
    "netflix": 0.20,
}

parser = argparse.ArgumentParser(description="Generate TEID-to-app mapping and profiles from PCAP stats.")
parser.add_argument("pcap_stats_folder", help="Directory containing <app>.pcap.stats.json files")
parser.add_argument("--total-teids", type=int, default=1000, help="Total number of TEIDs to assign (default: 1000)")
parser.add_argument("--apps", type=str, help="Comma-separated list of apps to include")
parser.add_argument("--scale-pps", type=float, default=1.0, help="Scale factor for per-app mean PPS")
parser.add_argument("--output-prefix", type=str, default=".", help="Output directory for JSON files")
args = parser.parse_args()

apps_filter = set(args.apps.split(",")) if args.apps else set(APP_QFI_MAP.keys())
selected_apps = [a for a in TEID_SHARE_PER_APP if a in apps_filter]

# Compute fair TEID counts from percentages
teid_counts = {app: int(args.total_teids * TEID_SHARE_PER_APP[app]) for app in selected_apps}
rounding_gap = args.total_teids - sum(teid_counts.values())
if rounding_gap > 0:
    teid_counts[selected_apps[-1]] += rounding_gap

teid_base = 0x2000
used_teids = set()
profiles = {}
teid_entries = []
total_scaled_pps = 0.0

for stat_file in sorted(glob.glob(os.path.join(args.pcap_stats_folder, "*.stats.json"))):
    app = os.path.basename(stat_file).replace(".pcap.stats.json", "")
    if app not in selected_apps:
        continue

    with open(stat_file) as f:
        stats = json.load(f)

    qfi = APP_QFI_MAP[app]
    qid = QFI_QID_MAP[qfi]
    count = teid_counts.get(app, 0)

    profiles[app] = {"qfi": qfi, "qid": qid, "stats": stats}
    scaled_pps = stats["pps"] * args.scale_pps
    profiles[app]["stats"]["pps"] = scaled_pps
    total_scaled_pps += scaled_pps * count

    for _ in range(count):
        while teid_base in used_teids:
            teid_base += 1
        teid_entries.append({"teid": teid_base, "app": app})
        used_teids.add(teid_base)
        teid_base += 1

# Write profiles.json
profiles_path = os.path.join(args.output_prefix, "profiles.json")
with open(profiles_path, "w") as f:
    json.dump(profiles, f, indent=2)

# Write teid_map.json
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

teid_map_path = os.path.join(args.output_prefix, "teid_map.json")
with open(teid_map_path, "w") as f:
    json.dump(teid_output, f, indent=2)

# Summary
print(f"[+] Wrote {len(profiles)} profiles to {profiles_path}")
print(f"[+] Wrote {len(teid_entries)} TEID entries to {teid_map_path}")
print(f"[✓] Estimated total PPS: {int(total_scaled_pps):,} packets/sec")
