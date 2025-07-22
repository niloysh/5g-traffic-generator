import subprocess
import pandas as pd
from pathlib import Path
from collections import deque


def get_packet_times_and_sizes(pcap_path):
    cmd = ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "frame.time_relative", "-e", "frame.len"]
    try:
        output = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {pcap_path.name}: {e}")
        return [], []

    times, sizes = [], []
    for line in output.strip().splitlines():
        try:
            t, s = line.strip().split("\t")
            times.append(float(t))
            sizes.append(int(s))
        except ValueError:
            continue
    return times, sizes


def estimate_trtcm_params(times, sizes):
    if len(times) < 2:
        return {"error": "Too few packets"}

    total_bits = sum(sizes) * 8
    duration = times[-1] - times[0]
    avg_bps = total_bits / duration if duration > 0 else 0

    # Sliding window for peak rate (1s)
    window = deque()
    peak_bps = 0
    for t, s in zip(times, sizes):
        while window and t - window[0][0] > 1.0:
            window.popleft()
        window.append((t, s))
        bits = sum(pkt_size for _, pkt_size in window) * 8
        peak_bps = max(peak_bps, bits)

    # Sliding window for burst size (100ms)
    burst_window = deque()
    max_burst_bytes = 0
    for t, s in zip(times, sizes):
        while burst_window and t - burst_window[0][0] > 0.1:
            burst_window.popleft()
        burst_window.append((t, s))
        burst_bytes = sum(pkt_size for _, pkt_size in burst_window)
        max_burst_bytes = max(max_burst_bytes, burst_bytes)

    return {
        "CIR_kbps": round(avg_bps / 1000, 2),
        "PIR_kbps": round(peak_bps / 1000, 2),
        "CBS_bytes": max_burst_bytes,
        "PBS_bytes": int(max_burst_bytes * 1.5),
    }


def main():
    pcap_dir = Path("../pcaps_new")
    results = []

    for pcap in sorted(pcap_dir.glob("*.pcap")):
        print(f"[INFO] Processing {pcap.name} ...")
        times, sizes = get_packet_times_and_sizes(pcap)
        params = estimate_trtcm_params(times, sizes)
        params["pcap_file"] = pcap.name
        results.append(params)

    df = pd.DataFrame(results)
    pd.set_option("display.max_columns", None)
    print("\n=== TrTCM Parameters ===\n")
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
