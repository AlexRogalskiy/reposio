#!/usr/bin/perl
$pattern = shift;
while(@fields = getpwent) {
	if($fields[6] =~ /$pattern/i and $fields[2] > 500) {
		print "$fields[6]\n"
	}
}