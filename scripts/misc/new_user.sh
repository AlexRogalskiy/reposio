#!/bin/bash
expiredate=$(date)+5
if[[ -z "$1" ]]; then
	echo ""
	echo "Please provide one file name"
	exit 1
fi

cat "$1" | while read username groupname realname
do
	if[[ -z $username || -z $groupname || -z $realname ]]; then
		continue
	fi
	result = $(egrep "^$username:" < /etc/passwd)
	if[[ -n "$result" ]]; then
		echo "User '$username' already exists"
		continue
	fi
	result = $(egrep "^$groupname:" < /etc/group)
	if[[ -z "$result" ]]; then
		groupadd "$groupname"
	fi
	useradd -c "$realname" \
			-d "/home/$username" \
			-e "$expiredate" \
			-f 365 \
			-g "$groupname" \
			-m \
			-s /bin/bash \
			"$username"
	if[[ $? == 0 ]]; then
		echo "User <$username> has been added"
	else
		echo "ERROR: adding user '$username' with (group '$groupname'), (name '$realname')"
		exit 1
	fi
done