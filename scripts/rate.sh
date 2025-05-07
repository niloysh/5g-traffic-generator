#!/bin/bash

INTERVAL="1"

if [ -z "$1" ]; then
    echo
    echo "Usage: $0 [network-interface]"
    echo
    echo "Example: $0 eth2"
    echo
    echo "Shows TX/RX rate in Mbps and Gbps"
    exit 1
fi

IF=$1

while true
do
    R1=$(cat /sys/class/net/$IF/statistics/rx_bytes)
    T1=$(cat /sys/class/net/$IF/statistics/tx_bytes)

    sleep $INTERVAL

    R2=$(cat /sys/class/net/$IF/statistics/rx_bytes)
    T2=$(cat /sys/class/net/$IF/statistics/tx_bytes)

    RX_BYTES=$((R2 - R1))
    TX_BYTES=$((T2 - T1))

    RX_Mbps=$(echo "scale=2; $RX_BYTES * 8 / 1000000" | bc)
    TX_Mbps=$(echo "scale=2; $TX_BYTES * 8 / 1000000" | bc)

    RX_Gbps=$(echo "scale=3; $RX_BYTES * 8 / 1000000000" | bc)
    TX_Gbps=$(echo "scale=3; $TX_BYTES * 8 / 1000000000" | bc)

    echo -e "TX: $TX_Mbps Mbps ($TX_Gbps Gbps)\tRX: $RX_Mbps Mbps ($RX_Gbps Gbps)"
done
