#!/bin/sh

# Copyright (c) 2014 Nordic Semiconductor. All Rights Reserved.
#   
# The information contained herein is property of Nordic Semiconductor ASA.
# Terms and conditions of usage are described in detail in NORDIC SEMICONDUCTOR STANDARD SOFTWARE LICENSE AGREEMENT.
# Licensees are granted free, non-transferable use of the information. NO WARRANTY of ANY KIND is provided. 
# This heading must NOT be removed from the file.
# 
# Description:
# ------------
# The script allows to perform DFU operation from the computer using Android device as a dongle.
# The script may be run on Linux or Mac.
#
# Requirements:
# -------------
# 1. Android device with Android version 4.3+ connected by USB cable with the PC
# 2. The path to Android platform-tools directory must be added to %PATH% environment variable
# 3. nRF Toolbox (1.11.0+) or nRF Connect (2.1.0+) application installed on the Android device
# 4. "Developer options" and "USB debugging" must be enabled on the Android device
#
# Usage:
# ------
# 1. Open command line
# 2. Type "sh dfu.sh -?" and press ENTER
#
# Android Debug Bridge (adb):
# ---------------------------
# You must have Android platform tools installed on the computer or the path to the adb application set in the PATH.
# Go to http://developer.android.com/sdk/index.html for more information how to install it on the computer.
# You do not need the whole ADT Bundle (with Eclipse or Android Studio). Only SDK Tools with Platform Tools are required.

# ==================================================================================
PROGRAM=$0
DEVICE=""
S_DEVICE=""
ADDRESS=""
HEX_FILE=""
HEX_PATH=""
NAME="DfuTarg"
INIT_FILE=""
INIT_PATH=""
E_INIT_FILE=""
TYPE=0

# ==================================================================================
# Common methods

intro() {
    echo "===================================="
    echo "Nordic Semiconductor DFU bash script"
    echo "===================================="
}

error() {
    exit 1
}

quit() {
    exit 0
}

usage() {
    echo "Usage: $PROGRAM [options] hex-file"
    echo "Options:"
    echo "      -d device serial number. Use \"adb devices\" to get list of serial numbers"
    echo "      -a target device address in XX:XX:XX:XX:XX:XX format"
    echo "      -n name optional device name"
    echo "      -t firmware_type 1=Soft Device, 2=Bootloader, 4=Application, 0 (default)=Auto or all from ZIP"
    echo "      -i init the init packet *.dat file"
}

# ==================================================================================
# Write intro
intro

# ==================================================================================
# Check ADB
adb devices > /dev/null 2>&1
if [ ! "$?" = "0" ] ; then
    echo "Error: adb is not recognized as an external command."
    echo "       Add [Android Bundle path]\\\android-sdk-macosx\\\platform-tools" to \$PATH
    error
fi

# ==================================================================================
# Parse options
while getopts ":d:a:n:t:i:" VALUE "$@"
do
    case $VALUE in
    d )
        DEVICE="$OPTARG"
        S_DEVICE="-s $OPTARG"
        ;;
    a ) ADDRESS="$OPTARG" ;;
    n ) NAME="$OPTARG" ;;
    t ) TYPE=$OPTARG ;;
    i ) 
        INIT_PATH="$OPTARG"
    	INIT_FILE=$(basename $INIT_PATH)
		E_INIT_FILE="-e no.nordicsemi.android.dfu.extra.EXTRA_INIT_FILE_PATH \"/sdcard/Nordic Semiconductor/Upload/$INIT_FILE\""
    	;;
    : ) echo "Error: Option -$OPTARG must have a string value.\n"
        usage
        error
        ;;
    ? ) usage
        quit
        ;;
    esac
done
shift $((OPTIND - 1))

# Get the HEX file name or write an error
if [ "$1" = "" ] ; then
    echo "Error: HEX file name not specified.\n"
    usage
    error
else
    HEX_PATH=$1
    HEX_FILE=$(basename $HEX_PATH)
fi

# ==================================================================================
if [ "$DEVICE" = "" ] ; then
    # Check if there is only one device connected
    C=$(adb devices | grep -e "device" -e "unauthorized" -e "emulator" | grep -c -v "devices")
    if [ "$C" = "0" ] ; then
        echo "Error: No device connected.";
        error
    fi
    if [ ! "$C" = "1" ] ; then
        echo "Error: More than one device connected."
        echo "       Specify the device serial number using -d option:"
        adb devices
        usage
        error
    fi
else
    # Check if specified device is connected
    C=$(adb devices | grep -c "$DEVICE")
    if [ "$C" = "0" ] ; then
        echo "Error: Device with serial number \"$DEVICE\" is not connected."
        adb devices
        error
    fi
fi

# ==================================================================================
# Copy selected file onto the device
printf "Copying \"$HEX_FILE\" to /sdcard/Nordic Semiconductor/Upload/..."
adb push $S_DEVICE $HEX_PATH "/sdcard/Nordic Semiconductor/Upload/$HEX_FILE" > /dev/null 2>&1
if [ "#?" = "1" ] ; then
    echo "FAIL"
    echo "Error: Device not found."
    error
else
    echo "OK"
fi

if [ ! "$INIT_FILE" = "" ] ; then
	printf "Copying \"$INIT_FILE\" to /sdcard/Nordic Semiconductor/Upload/..."
	adb push $S_DEVICE $INIT_PATH "/sdcard/Nordic Semiconductor/Upload/$INIT_FILE" > /dev/null 2>&1
	if [ "#?" = "1" ] ; then
	    echo "FAIL"
	    echo "Error: Device not found."
	    error
	else
	    echo "OK"
	fi
fi

if [ "$ADDRESS" = "" ] ; then
	# Start DFU Initiator activity if no target device specified
    printf "Starting DFU Initiator activity..."
    adb $S_DEVICE shell am start -a no.nordicsemi.android.action.DFU_UPLOAD --ei no.nordicsemi.android.dfu.extra.EXTRA_FILE_TYPE $TYPE -e no.nordicsemi.android.dfu.extra.EXTRA_FILE_PATH "/sdcard/Nordic Semiconductor/Upload/$HEX_FILE" $E_INIT_FILE | grep "Error" > /dev/null 2>&1
else
	# Start the DFU service directly
    printf "Starting DFU service..."
    adb $S_DEVICE shell am startservice -n no.nordicsemi.android.mcp/.dfu.DfuService -a no.nordicsemi.android.action.DFU_UPLOAD --ei no.nordicsemi.android.dfu.extra.EXTRA_FILE_TYPE $TYPE -e no.nordicsemi.android.dfu.extra.EXTRA_DEVICE_ADDRESS $ADDRESS -e no.nordicsemi.android.dfu.extra.EXTRA_DEVICE_NAME $NAME -e no.nordicsemi.android.dfu.extra.EXTRA_FILE_PATH "/sdcard/Nordic Semiconductor/Upload/$HEX_FILE" $E_INIT_FILE | grep "Error" > /dev/null 2>&1
fi

if [ "$?" = "0" ] ; then
    echo "FAIL"
    echo "Error: Required application not installed."
    error
else
    echo "OK"
    echo "Select DFU target on your Android device to start upload."
fi