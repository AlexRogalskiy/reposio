@ECHO OFF
CLS

SETLOCAL ENABLEDELAYEDEXPANSION
SET current=%~n0
SET parent=%~dp0

:: GitHub Pushing
ECHO [94m Updating "%parent%"[0m

PAUSE

FOR /d %%i IN (%1*) DO call :GIT %%i %2

GOTO END

:GIT
SET t=%~nx1
IF "%t:~0,3%" == "%2" (
	GOTO :GIT_PULL_TAG
)
GOTO :EOF

:GIT_PULL_TAG
ECHO [43m Pulling from repository ["%1"] [0m
CD "%1" & CMD /c git pull
ECHO [43m Pull finished[0m
ECHO --------------------------------------------------------------------------
GOTO :EOF

:END
ECHO [94m Updating "%parent%" finished[0m