@echo off
REM ��ɾ��npWebClient_9000.dll���ļ�
del "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" 

if exist "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" set success=0
if not exist "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" set success=1

xcopy "%systemdrive%\Program Files\WebClient_9000\WebClient_9000\delFile.exe" "%systemdrive%\Program Files\WebClient_9000\" /e /y

if exist "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" start "" "%systemdrive%\Program Files\WebClient_9000\delFile.exe"
if %success%==0 exit

REM ���ⲽ��ʱ��˵����ʱ���Խ����ļ��滻
xcopy "%systemdrive%\Program Files\WebClient_9000\WebClient_9000\*.*" "%systemdrive%\Program Files\WebClient_9000\" /e /y

REM ע��acitvex�ؼ�
regsvr32 /S "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll"

REM ���firefox plugin ע���
reg delete "HKEY_CURRENT_USER\SOFTWARE\MozillaPlugins\@tvt.cn/npWebClient_9000" /va /f > nul
reg add "HKEY_CURRENT_USER\SOFTWARE\MozillaPlugins\@tvt.cn/npWebClient_9000" /v "Path" /t reg_sz /d "%systemdrive%\Program Files\WebClient_9000\npWebClient_9000.dll" /f

REM ��ӿ������ɾ������
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npWebClient_9000" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npWebClient_9000" /v "DisplayName" /t reg_sz /d "WebClient_9000" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\npWebClient_9000" /v "UninstallString" /t reg_sz /d "%systemdrive%\Program Files\WebClient_9000\uninstall.cmd" /f

REM ɾ�������ļ�
rd "%systemdrive%\Program Files\WebClient_9000\WebClient_9000" /s /q 

REM ɾ������
del setup.cmd