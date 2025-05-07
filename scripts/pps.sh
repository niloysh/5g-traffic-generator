#!/bin/bash

# Interval of calculation in seconds
INTERVAL="1"
 
if [ -z "$1" ]; then
        echo
        echo usage: $0 [network-interface]
        echo
        echo e.g. $0 eth0
        echo
        echo shows packets-per-second
        exit
fi
 
IF=$1
 
while true
do
        R1=`cat /sys/class/net/$1/statistics/rx_packets`
        T1=`cat /sys/class/net/$1/statistics/tx_packets`
        
        sleep $INTERVAL
        
        R2=`cat /sys/class/net/$1/statistics/rx_packets`
        T2=`cat /sys/class/net/$1/statistics/tx_packets`
        
        TXPPS=`expr $T2 - $T1`
        RXPPS=`expr $R2 - $R1`

        echo -e "TX $TXPPS\tpkts/s RX $RXPPS\tpkts/s"
done