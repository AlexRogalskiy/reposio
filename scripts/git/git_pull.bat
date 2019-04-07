@ECHO OFF
CLS

SETLOCAL ENABLEEXTENSIONS
SET current=%~n0
SET parent=%~dp0

:: GitHub Pulling
ECHO [95m Pulling from "%parent%"[0m

PAUSE

FOR /d %%i IN (%parent%*) DO (ECHO [41m Fetching from ["%%i"] [0m & CD "%%i" & CMD /c git pull)

ECHO [95m Pull finished[0m

PAUSE