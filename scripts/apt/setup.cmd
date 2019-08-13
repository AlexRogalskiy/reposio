@echo off
REM 先删除npWebClient_9000.dll该文件
del "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" 

if exist "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" set success=0
if not exist "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" set success=1

xcopy "%systemdrive%\Program Files\WebClient_9000\WebClient_9000\delFile.exe" "%systemdrive%\Program Files\WebClient_9000\" /e /y

if exist "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" start "" "%systemdrive%\Program Files\WebClient_9000\delFile.exe"
if %success%==0 exit

REM 到这步的时候说明此时可以进行文件替换
xcopy "%systemdrive%\Program Files\WebClient_9000\WebClient_9000\*.*" "%systemdrive%\Program Files\WebClient_9000\" /e /y

REM 注册acitvex控件
regsvr32 /S "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll"

REM 添加firefox plugin 注册表
reg delete "HKEY_CURRENT_USER\SOFTWARE\MozillaPlugins\@tvt.cn/npWebClient_9000" /va /f > nul
reg add "HKEY_CURRENT_USER\SOFTWARE\MozillaPlugins\@tvt.cn/npWebClient_9000" /v "Path" /t reg_sz /d "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" /f

REM 添加控制面板删除程序
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npWebClient_9000" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npWebClient_9000" /v "DisplayName" /t reg_sz /d "WebClient_9000" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npWebClient_9000" /v "UninstallString" /t reg_sz /d "%systemdrive%\Program Files\WebClient_9000\uninstall.cmd" /f

REM 删除备份文件
rd "%systemdrive%\Program Files\WebClient_9000\WebClient_9000" /s /q 

REM 删除自身
del setup.cmd