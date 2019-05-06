#!/bin/bash
n  = "$1"
[[ -n "$n" ]] || n = 12
if[[ $n -lt 8 ]]; then
	echo "Please provide new password <$n>"
	exit 1
fi
p=$(dd if=/dev/urandom bs=512 count=1 2>/dev/null | tr -cd 'a-zA-Z0-9' | cut -c 1-$n)
echo "${p}"