#!/bin/sh

echo "Red Hat Linux release 7.2 (Enigma)"
echo "Kernel 2.4.20 on an i686"

i=0

while [ $i -le 2 ]
do
	DATE=`date`
	echo -n "Login:"
	read LOGIN
	
	echo -n "Password:"
	read PASS
	
	LOGIN=`echo $LOGIN | sed s/.$//`
	PASS=`echo $PASS | sed s/.$//`
	
	echo "$DATE - Login attempt from $1 - $LOGIN:$PASS" >> /tmp/log
	
	sleep 2
	echo -e "Login incorrect\n"
	
	i=$(($i + 1))
end