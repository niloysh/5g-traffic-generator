import json
import subprocess
import time
import threading
import random
import signal
import os
import tempfile
from datetime import datetime

CONFIG_PATH = "config.json"
REPLAY_BIN = "../build/gtpu_encap_replay"
stop_flag = False
threads = []


def log(flow_id, msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [Flow {flow_id}] {msg}")


def get_interface_list():
    return os.listdir("/sys/class/net")


def replay_loop(flow_id, pcap, teid, qfi, iface, qfi_file, min_idle, max_idle, end_time):
    # Initial randomized idle before first replay
    if max_idle > 0 and not stop_flag:
        first_sleep = random.uniform(min_idle, max_idle)
        log(flow_id, f"Initial idle for {first_sleep:.1f}s before first replay")
        slept = 0
        while slept < first_sleep and not stop_flag and time.time() < end_time:
            time.sleep(min(1.0, first_sleep - slept))
            slept += 1

    while not stop_flag and time.time() < end_time:
        cmd = [REPLAY_BIN, pcap, iface, "--teid", teid, "--qfi", str(qfi)]
        if qfi_file:
            cmd += ["--qfi-file", qfi_file]

        log(flow_id, f"Replaying {pcap} (TEID={teid}, QFI={qfi})")
        proc = subprocess.Popen(cmd)

        # Poll the replay process for early Ctrl+C or timeout
        while proc.poll() is None:
            if stop_flag or time.time() >= end_time:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                log(flow_id, "Replay terminated early")
                return
            time.sleep(1)

        # Sleep (non-blocking, short chunks)
        if max_idle > 0 and not stop_flag:
            sleep_time = random.uniform(min_idle, max_idle)
            log(flow_id, f"Sleeping for {sleep_time:.1f}s")
            slept = 0
            while slept < sleep_time and not stop_flag and time.time() < end_time:
                time.sleep(min(1.0, sleep_time - slept))
                slept += 1


def signal_handler(sig, frame):
    global stop_flag
    print("\n[INFO] Caught Ctrl+C — stopping all flows...")
    stop_flag = True


def cleanup_temp_qfi_files():
    for f in os.listdir("/tmp"):
        if f.startswith("qfi_ue") and f.endswith(".txt"):
            try:
                os.remove(os.path.join("/tmp", f))
            except Exception as e:
                print(f"[WARN] Could not delete {f}: {e}")


def main():
    global stop_flag
    signal.signal(signal.SIGINT, signal_handler)

    with open(CONFIG_PATH) as f:
        cfg = json.load(f)

    iface = cfg["interface"]
    duration_sec = cfg["duration_minutes"] * 60
    base_teid = cfg["base_teid"]
    ue_count = cfg["ue_count"]
    qos_profiles = cfg["qos_profiles"]
    end_time = time.time() + duration_sec

    # Check interface exists
    if iface not in get_interface_list():
        print(f"[ERROR] Interface '{iface}' not found. Check config.json.")
        return

    # Clean up any leftover qfi files
    cleanup_temp_qfi_files()

    print(f"[INFO] Launching {ue_count} UEs × 3 flows each on interface {iface}")
    print(f"[INFO] Total runtime: {cfg['duration_minutes']} minutes\n")

    for ue_idx in range(ue_count):
        selected_profiles = random.sample(qos_profiles, 3)

        for profile in selected_profiles:
            qfi = profile["qfi"]
            pcap = profile["pcap"]
            idle_range = profile.get("idle_range", [0, 0])

            flow_id = f"{ue_idx:03d}_qfi{qfi}"
            teid = hex(base_teid + ue_idx)
            qfi_file = f"/tmp/qfi_ue{ue_idx}_qfi{qfi}.txt"

            try:
                with open(qfi_file, "w") as f:
                    f.write(str(qfi))
            except Exception as e:
                print(f"[ERROR] Could not write QFI file: {qfi_file}: {e}")
                continue

            t = threading.Thread(
                target=replay_loop,
                args=(flow_id, pcap, teid, qfi, iface, qfi_file, idle_range[0], idle_range[1], end_time),
            )
            t.start()
            threads.append(t)
            time.sleep(0.05)

    for t in threads:
        t.join()

    print("\n[INFO] All flows stopped. Cleaning up.")
    cleanup_temp_qfi_files()
    print("[INFO] Done.")


if __name__ == "__main__":
    main()
