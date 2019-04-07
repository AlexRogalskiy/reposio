#!/bin/bash

. ./etc/hw.config

modules_start() {
	echo -n "[i] Loading kernel modules: "
	for MODULE in $KERNEL_MODULES; do
		echo -n "$MODULE"
		$MODPROBE $MODULE
	done
	echo
}
modules_stop() {
	echo "[i] Unloading kernel modules..."
	$MODPROBE -r $KERNEL_MODULES
}

management_start() {
	echo "[i] Starting management interface ($MANAGEMENT_IF)..."
	$IFCONFIG $MANAGEMENT_IF $MANAGEMENT_IP netmask $MANAGEMENT_NETMASK up
	$IPTABLES -I INPUT -i $MANAGEMENT_IF -j REJECT
	$IPTABLES -I INPUT -i $MANAGEMENT_IF -s $MANAGER_IP -j ACCEPT
}

management_stop() {
	echo "[i] Stopping management interface ($MANAGEMENT_IF)..."
	$IFCONFIG $MANAGEMENT_IF down
	$IPTABLES -D INPUT -i $MANAGEMENT_IF -j REJECT
	$IPTABLES -D INPUT -i $MANAGEMENT_IF -s $MANAGER_IP -j ACCEPT
}

bridge_start() {
	echo "[i] Starting bridge interface ($BRIDGE_IF: $INSINDE_IF, $OUTSIDE_IF)..."
	$IFCONFIG $INSIDE_IF 0.0.0.0 up
	$IFCONFIG $OUTSIDE_IF 0.0.0.0 up
	$BRCTL addbr $BRIDGE_IF
	$BRCTL addif $BRIDGE_IF $INSIDE_IF
	$BRCTL addif $BRIDGE_IF $OUTSIDE_IF
	$IFCONFIG $BRIDGE_IF 0.0.0.0 up
	$IPTABLES -P FORWARD DROP
}

bridge_stop() {
	echo "[i] Stopping bridge interface ($BRIDGE_IF: $INSIDE_IF, $OUTSIDE_IF)..."
	$IFCONFIG $BRIDGE_IF down
	$BRCTL delbr $BRIDGE_IF
	$IFCONFIG $OUTSIDE_IF down
	$IFCONFIG $INSIDE_IF down
	$IPTABLES -P FORWARD ACCEPT
}

case "$1" in
	'start')
		modules_start
		
		management_start
		bridge_start
		;;
	'stop')
		modules_stop
		
		bridge_stop
		management_stop
		;;
	*)
		echo "[i] Usage $0 start | stop"
esac