#!/bin/bash

. ./hw.config

tcpdump_start() {
	echo "[i] Starting tcpdump on $OUTSIDE_IF..."
	$TCPDUMP -i $OUTSIDE_IF -s 0 -w $TCPDUMP_LOG 2> /dev/null &
	echo $! > $TCPDUMP_PID_FILE
}

tcpdump_stop() {
	echo "[i] Stopping tcpdump..."
	$KILL `cat $TCPDUMP_PID_FILE`
	rm $TCPDUMP_PID_FILE
}

case "$1" in
	'start')
		tcpdump_start
		;;
	'stop')
		tcpdump_stop
		;;
	*)
		echo "[!] Usage $0 start | stop"
esac