#!/usr/bin/env python3

# example: sudo python3 scripts/replay_all_gtpu_pcaps.py --interface enp2s0f0 --pcap-dir ./encapsulated --replay-binary ./build/gtpu_replay --max-workers 20
import os
import signal
import subprocess
import argparse
from pathlib import Path
from threading import Thread
import time

running_processes = []


def parse_args():
    parser = argparse.ArgumentParser(description="Replay all encapsulated GTP-U pcaps in parallel.")
    parser.add_argument(
        "--pcap-dir", type=Path, default=Path("./encapsulated"), help="Directory containing GTP-U pcap files"
    )
    parser.add_argument("--interface", required=True, help="Network interface to send packets on (e.g., enp2s0f0)")
    parser.add_argument("--replay-binary", type=Path, default=Path("./gtpu_replay"), help="Path to gtpu_replay binary")
    parser.add_argument("--max-workers", type=int, default=None, help="Max concurrent replay threads (default: all)")
    parser.add_argument("--stagger", type=float, default=0.25, help="Stagger start time between replays (in seconds)")
    return parser.parse_args()


def run_replay(pcap_file, interface, replay_binary):
    print(f"[+] Starting replay: {pcap_file.name}")
    proc = subprocess.Popen(["sudo", str(replay_binary), str(pcap_file), interface], preexec_fn=os.setsid)
    running_processes.append(proc)
    proc.wait()
    print(f"[✔] Finished: {pcap_file.name}")


def main():
    args = parse_args()
    pcap_files = sorted(args.pcap_dir.glob("teid_0x*.pcap"))
    max_workers = args.max_workers or len(pcap_files)

    if not pcap_files:
        print(f"[!] No PCAPs found in {args.pcap_dir}")
        return

    threads = []

    def signal_handler(sig, frame):
        print("\n[!] Ctrl+C caught, terminating all replay processes...")
        for proc in running_processes:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception as e:
                print(f"Failed to terminate PID {proc.pid}: {e}")
        for t in threads:
            t.join()
        print("[✓] All processes cleaned up.")
        exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    for i, pcap_file in enumerate(pcap_files):
        while len(threads) >= max_workers:
            threads = [t for t in threads if t.is_alive()]
            time.sleep(0.1)

        t = Thread(target=run_replay, args=(pcap_file, args.interface, args.replay_binary))
        t.start()
        threads.append(t)

        if args.stagger > 0:
            time.sleep(args.stagger)

    for t in threads:
        t.join()

    print("[✓] All PCAP replays completed.")


if __name__ == "__main__":
    main()
