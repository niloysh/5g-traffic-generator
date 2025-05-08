# 5G Traffic Generator

A high-performance toolkit for generating **5G GTP-U traffic** with fully formed headers, including TEID and QFI. Designed for testing 5G user plane functionality, telemetry, and network slicing experiments.

This toolkit emits wire-format GTP-U packets with TEID and QFI headers that can be observed in Wireshark, replayed over real networks, and used to test slice-aware telemetry, queue-level behavior, and congestion response in realistic 5G user plane scenarios.

---

## Features
- **GTP-U headers** with TEID and optional QFI extension
- **AF_PACKET + multithreading** for high performance (~1Mpps with 4-6 cores)
- **CBR mode** for constant bit rate traffic with varying TEIDs and QFIs
- **Profile-driven mode** for more realistic traffic based on PCAP traces
- **Anomaly injection** for triggering bursts, overloads, and queue stress per TEID/QFI
- **Tools** for encapsulation, replay, and analysis of PCAP traces

## Build Instructions

```bash
sudo apt-get install libpcap-dev libjansson-dev
mkdir build && cd build
cmake ..
make
```

After building, run a simple test to confirm GTP-U packets are being generated correctly:

```bash
./scripts/gtpu_sender_test.sh
```

You should see output like:

```
Sent GTP-U packet 1 with TEID=0x100 and QFI=5
Sent GTP-U packet 2 with TEID=0x101 and QFI=6
Sent GTP-U packet 3 with TEID=0x102 and QFI=7
Sent GTP-U packet 4 with TEID=0x103 and QFI=8
```

You should be able to caputure these packets with Wireshark on the specified interface.

---

## Usage Options

### 1. CBR Traffic (Simple, Repeatable)
Use `gtpu_cbr_generator` to send constant bit rate GTP-U traffic with fixed TEIDs and QFIs.

```bash
sudo ./build/gtpu_cbr_generator --interface eth0 --pps 500000 ...
```

---

### 2. Profile-Driven Traffic (Realistic)
Use traffic traces to model application behavior. This approach uses JSON configs to control per-TEID behavior.

#### Step-by-step:

1. **Get traffic traces**  
   Use your own PCAPs or download datasets such as [5G Traffic Dataset](https://ieee-dataport.org/documents/5g-traffic-datasets).
   (See `sample_pcaps/` for small examples.)

2. **Extract stats**  
   Analyze the PCAPs with:
   ```bash
   ./build/pcap_analyzer trace.pcap
   ```
   Generates `trace.pcap.stats.json`

3. **Generate configs**  
   Use:
   ```bash
   python3 scripts/generate_teid_config.py <pcap_stats_dir>
   ```
   Outputs:
   - `profiles.json`: packet size/gap histograms
   - `teid_map.json`: TEID ↔ QFI/app mapping
  
  See `config/` for examples.

4. **Run profile-based sender**  
   ```bash
   sudo ./build/gtpu_traffic_generator config/profiles.json config/teid_map.json eth0 192.168.1.1 192.168.1.2
   ```

### 3. PCAP Encapsulation & Replay

Use real application traces to simulate 5G user plane traffic.

#### Step 1: Encapsulate a PCAP

Wrap any packet trace with GTP-U, IP/UDP, and Ethernet headers using:

```bash
./build/gtpu_encapsulator input.pcap output_gtpu.pcap --teid 0x2001 --qfi 1
```

This produces a GTP-U-wrapped pcap (`output_gtpu.pcap`) that is Wireshark-compatible and ready for replay.

#### Step 2: Replay

Send the encapsulated packets on the wire via:

```bash
sudo ./build/gtpu_replay output_gtpu.pcap eth0
```

#### Step 3: Parallel Replay

Use the helper script to replay all GTP-U PCAPs in a directory:

```bash
sudo python3 scripts/replay_all_gtpu_pcaps.py \
  --interface eth0 \
  --pcap-dir ./encapsulated \
  --replay-binary ./build/gtpu_replay \
  --max-workers 8
```

Each PCAP is replayed in a separate process, with optional staggering. Useful for load or slice simulation.

### 4. Anomaly Injection

Use `gtpu_anomaly_injector` to simulate short bursts tied to specific TEIDs or QFIs:

```bash
sudo ./build/gtpu_anomaly_injector \
  --interface eth0 \
  --src-ip 192.168.1.1 \
  --dst-ip 192.168.1.2 \
  --teids 0x2000,0x2001 \
  --qfis 1,2 \
  --pps 600000 \
  --duration 3 \
  --num-threads 2
```

This tool is useful for testing bursty conditions.

---

## Tools Overview

| Tool                     | Description                                             |
| ------------------------ | ------------------------------------------------------- |
| `gtpu_cbr_generator`     | Constant-rate traffic with fixed TEIDs and QFIs         |
| `gtpu_traffic_generator` | Profile-driven sender with per-TEID app behavior        |
| `gtpu_encapsulator`      | Wraps existing PCAPs in GTP-U, IP/UDP, Ethernet headers |
| `gtpu_replay`            | Replays encapsulated PCAPs over the network             |
| `pcap_analyzer`          | Extracts stats (packet size, PPS, gaps) from PCAPs      |
| `gtpu_sender_test`       | Minimal functional test for TEID/QFI generation         |
| `gtpu_anomaly_injector`  | Injects bursts or micro-anomalies for telemetry testing |

---


