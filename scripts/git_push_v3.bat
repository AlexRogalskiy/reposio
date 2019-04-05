@ECHO OFF
CLS

SETLOCAL ENABLEDELAYEDEXPANSION
SET current=%~n0
SET parent=%~dp0

:: GitHub Pushing
ECHO [94m Updating "%parent%"[0m

PAUSE

FOR /d %%i IN (%1*) DO call :GIT %%i

GOTO END

:GIT
SET t=%~nx1
IF "%t:~0,3%" == "pem" (
	GOTO :GITPUSH
)
GOTO :EOF

:GITPUSH
ECHO [43m Pushing to repository ["%1"] [0m
CD "%1" & CMD /c git add . & CMD /c git commit -m "Changeset to project structure" & CMD /c git push
ECHO [43m Push finished[0m
ECHO --------------------------------------------------------------------------
GOTO :EOF

:END
ECHO [94m Updating "%parent%" finished[0m