@ECHO OFF
CLS

SETLOCAL ENABLEDELAYEDEXPANSION
SET current=%~n0
SET parent=%~dp0

:: GitHub Pushing
ECHO [94m Update to "%parent%"[0m

PAUSE

FOR /d %%i IN (%parent%*) DO call :PUSHTAG %%i

GOTO END

:PUSHTAG
SET t=%~nx1
IF "%t:~0,1%" == "_" (
	GOTO :EOF
) ELSE (
	GOTO :GIT
)

:GIT
ECHO [43m Pushing to repository ["%1"] [0m
CD "%1" & CMD /c git add . & CMD /c git commit -m "Changeset to project structure" & CMD /c git push
ECHO [43m Push finished[0m
ECHO --------------------------------------------------------------------------
GOTO :EOF

:END
ECHO [94m Push to "%parent%" finished[0m