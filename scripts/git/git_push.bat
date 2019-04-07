@ECHO OFF
CLS

SETLOCAL ENABLEEXTENSIONS
SET current=%~n0
SET parent=%~dp0

:: GitHub Pushing
ECHO [95m Pushing to "%parent%"[0m

PAUSE

FOR /d %%i in (%parent%*) DO (ECHO [41m Pushing to ["%%i"] [0m & CD "%%i" & CMD /c git add . & CMD /c git commit -m "Changeset to project structure" & CMD /c git push)

ECHO [95m Push finished[0m

PAUSE