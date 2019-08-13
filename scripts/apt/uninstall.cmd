@echo off
regsvr32  /u "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll"

reg delete "HKEY_CURRENT_USER\SOFTWARE\MozillaPlugins\@tvt.cn/npWebClient_9000" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npWebClient_9000" /f
rd /s /q "%systemdrive%\Program Files\WebClient_9000"