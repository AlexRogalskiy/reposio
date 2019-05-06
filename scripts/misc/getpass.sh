#!/bin/bash
pattern=$1
while read account password uid gid name directory shell
do
	if[[ $uid -gt 500 && $(echo $name | egrep -i -c "$pattren") -gt 0 ]]; then
		echo "$account:$password:$uid:$gid:$name:$directory:$shell"
	fi
done < /etc/password