"""
This script processes .pcap files and extracts the first 'n' packets from each file using tshark.
This helps downsize a single large pcap file into a smaller one so we can have multiple files for different TEIDs.
@example: python3 scripts/prepare_pcaps.py --num 1000000 --directory ./pcaps
"""

import os
import subprocess
import argparse

def extract_n_packets(directory, num_packets):
    """
    For each .pcap or .pcapng file in the directory, extract the first
    'num_packets' using tshark and overwrite the original file.
    """
    for filename in os.listdir(directory):
        if filename.endswith(".pcap") or filename.endswith(".pcapng"):
            path = os.path.join(directory, filename)
            tmp_path = path + ".tmp"
            print(f"Processing: {filename}")
            try:
                subprocess.run(
                    ["tshark", "-r", path, "-c", str(num_packets), "-w", tmp_path],
                    check=True, capture_output=True
                )
                os.replace(tmp_path, path)
                print(f"Done: {filename}")
            except subprocess.CalledProcessError as e:
                print(f"Error processing {filename}: {e}")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except FileNotFoundError:
                print("tshark not found. Make sure it is installed and in PATH.")
                return

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", help="Directory with pcap files")
    parser.add_argument("--num", type=int, default=1_000_000,
                        help="Number of packets to keep per file (default: 1,000,000)")
    args = parser.parse_args()

    if os.path.isdir(args.directory) and args.num > 0:
        extract_n_packets(args.directory, args.num)
    else:
        print("Invalid directory or packet count.")
