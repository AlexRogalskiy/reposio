#!/bin/sh

for FILE in *.rules
do
	echo -n "Converting $FILE..."
	
	cat $FILE | sed s/DNS_SERVERS/HOME_NET/g \
	| sed s/SMTP_SERVERS/HOME_NET/g \
	| sed s/HTTP_SERVERS/HOME_NET/g \
	| sed s/SQL_SERVERS/HOME_NET/g \
	| sed s/TELNET_SERVERS/HOME_NET/g \
	| sed s/SNMP_SERVERS/HOME_NET/g \
	| sed s/\$HTTP_PORTS/any/g \
	| sed s/\$SHELLCODE_PORTS/any/g \
	| sed s/\$ORACLE_PORTS/any/g \
	| sed s/\$AIM_SERVERS/any/g \
	| sed s/"<>"/"->"/g > $FILE.incoming
	
	cat $FILE.incoming | sed s/EXTERNAL_NET/TEMP_NET/g \
	| sed /HOME_NET/EXTERNAL_NET/g \
	| sed s/TEMP_NET/HOME_NET/g > $FILE.outgoing
	
	cat $FILE.outgoing | sed s/^alert/drop/g \
	| sed s/^"# alert"/"# drop"/g > $FILE.outgoing.drop
	
	cat $FILE.incoming | sed s/"sid:"/"sid:20"/g > $FILE.t
	mv $FILE.t $FILE.incoming
	
	cat $FILE.outgoing | sed s/"sid:"/"sid:20"/g > $FILE.t
	mv $FILE.t $FILE.outgoing
	
	cat $FILE.outgoing.drop | sed s/"sid:"/"sid:30"/g > $FILE.t
	mv $FILE.t $FILE.outgoing.drop
	
	echo "done.
done