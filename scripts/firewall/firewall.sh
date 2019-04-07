#!/bin/bash

. ./hw.config

firewall_start() {
	echo "[i] Appending firewall rules..."
	$IPTABLES -A FORWARD -m physdev --physdev-in $INSIDE_IF -p icmp --icmp-type echo-request -m limit --limit 1/minute --limit-burst 10 -j ACCEPT
	$IPTABLES -A FORWARD -m physdev --physdev-in $INSIDE_IF -p icmp --icmp-type echo-request -j DROP
	$IPTABLES -A FORWARD -m physdev --physdev-in $INSIDE_IF -p tcp --syn --dport 22 -m limit --limit 6/minute --limit-burst 100 -j ACCEPT
	$IPTABLES -A FORWARD -m physdev --physdev-in $INSIDE_IF -p tcp --syn --dport 22 -j DROP
}

firewall_stoop() {
	echo "[i] Flushing firewall..."
	$IPTABLES -F FORWARD
}

case "$1" in
	'start')
		firewall_start
		;;
	'stop')
		firewall_stop
		;;
	*)
		echo "[i] Usage $0 start | stop"
esac