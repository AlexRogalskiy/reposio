#!/bin/bash

. ./hw.config

snort_start() {
	echo "[i] Starting Snort..."
	$IPTABLES -A FORWARD -j QUEUE
	$SNORT -c $SNORT_CONFIG -l $SNORT_LOG -Q -K ascii -A $SNORT_LOG_TYPE -N -D -S HOME_NET=$HONEYPOT_IP -S EXTERNAL_NET=any &> /dev/null &
}

snort_stop() {
	echo "[i] Stopping Snort..."
	$KILL `cat $SNORT_PID_FILE`
	$IPTABLES -D FORWARD -j QUEUE
}

case "$1" in
	'start')
		snort_start
		;;
	'stop')
		snort_stop
		;;
	*)
		echo "[!] Usage $0 start | stop"
esac
		
