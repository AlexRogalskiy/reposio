@echo off
set /p TELNET_DATA=
echo Red Hat Linux release 5.1 (Manhattan)
echo Kernel 2.0.34 on an i586
echo .

date /T >> log.txt
time /T >> log.txt

set /p LOGIN=login:
set /p PASSWORD=Password:
echo Login attempt - %LOGIN%:%PASSWORD% >> log.txt
echo . >> log.txt

echo Login incorrect