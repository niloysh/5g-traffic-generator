# 5g-traffic-generator
A traffic generation toolkit for sending GTP-U packets with configurable TEID and QFI values. Useful for 5G core and transport testing, including slicing experiments.

Employs `AF_PACKET` for direct interaction with the network interface, enabling efficient packet transmission. Tools like `gtpu_cbr_generator.c` allows for scaling performance across multiple CPU cores, and can reach 1Mpps+ on a multi-core system.

## Dependencies
Make sure `libpcap` development headers are installed:

```bash
sudo apt-get install libpcap-dev
```

## Quick Start
```
mkdir build
cd build
cmake ..
make
```

## Run
You can use the helper scripts in the scripts/ directory. For example:
```bash
./scripts/gtpu_sender_test.sh
```
This script sends GTP-U packets to the destination IP/port specified.

## Tools
- `gtpu_sender_test`: Minimal GTP-U sender for basic functional tests.
- `gtpu_cbr_generator`: Sends constant bit rate GTP-U traffic with multiple TEIDs and QFIs.
- `pcap_analyzer`: Parses and analyzes PCAP traces to extract traffic statistics.
- `gtpu_encapsulator`: Wraps PCAP files in GTP-U + outer IP/UDP/Ethernet headers.


## Customization
To change source/destination IP or MAC addresses, open the relevant `.c` source file (e.g., `src/gtpu_cbr_generator.c`) and modify the variables. Then recompile the code.
