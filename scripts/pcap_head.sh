#!/bin/bash
# Extract first 50 packets from a pcap file
# Usage: ./pcap_head.sh input.pcap output.pcap
input="$1"
output="$2"
count=50
[ -f "$input" ] && tcpdump -r "$input" -c "$count" -w "$output" && echo "Extracted first $count to $output" || echo "Error"