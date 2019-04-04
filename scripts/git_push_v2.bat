@ECHO OFF
CLS

SETLOCAL ENABLEDELAYEDEXPANSION
SET current=%~n0
SET parent=%~dp0

:: GitHub Pushing
ECHO [95m Pushing to "%parent%"[0m

PAUSE

FOR /d %%i IN (%parent%*) DO call :PUSHTAG %%i
GOTO END

:PUSHTAG
SET t=%~nx1
IF "%t:~0,1%" == "_" (
	GOTO :EOF
) ELSE (
	ECHO [41m Pushing to ["%1"] [0m
	CD "%1" & CMD /c git add . & CMD /c git commit -m "Changeset to project structure" & CMD /c git push
)

:END
ECHO [95m Push finished[0m
