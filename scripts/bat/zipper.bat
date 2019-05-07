@echo off

setlocal enableextensions enabledelayedexpansion

rem
rem Display instructions when no parameter is given.
rem
if "%1" equ "" (
    echo Syntaxe : od.bat ^<directory mask>^
    echo Exemple : od.bat *
    goto :Eof
)

rem
rem Setting the PATH environment variable for this batch file for accessing 7za.exe.
rem
path=c:\temp;%PATH%

rem
rem Removing quotes from the given command line parameter path.
rem
set root=%1
set root=%root:~%1
set root=%root:~0,-1%

rem Searching directory structure from root for subfolders and zipfiles, then extracting the zipfiles into a subfolder of the same name as the zipfile.
for /F "delims==" %%d in ('dir /ogne /ad /b /s %root%') do (
    echo Traitement du dossier : "%%d"

    for /F "delims==" %%f in ('dir /b "%%d\*.zip"') do (
        rem Getting filename without extension.
        set subfolder=~n%f
        mkdir "%%d\%subfolder%"
        rem Extracting zipfile content to the newly created folder.
        7za.exe e "%%d\%%f" -o"%%d\%subfolder%"
    )
)

:Eof

endlocal