@echo off
set WDK=C:\Program Files (x86)\Windows Kits\10
set MSVC=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.35.32215

"%MSVC%\bin\Hostx64\x64\cl.exe" /c ^
    /I"%WDK%\Include\10.0.22621.0\km" ^
    /I"%WDK%\Include\10.0.22621.0\km\crt" ^
    /I"%WDK%\Include\10.0.22621.0\shared" ^
    /DKERNEL_MODE /DNDIS_MINIPORT_DRIVER /DNDIS630_MINIPORT=1 ^
    /Fo thor_lwf.obj ^
    thor_lwf.c

"%MSVC%\bin\Hostx64\x64\link.exe" /OUT:thor_lwf.sys ^
    /NOLOGO /NODEFAULTLIB ^
    /SECTION:INIT,d /OPT:REF /OPT:ICF ^
    /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text ^
    /MACHINE:X64 /ENTRY:DriverEntry /SUBSYSTEM:NATIVE,6.01 ^
    /RELEASE ^
    thor_lwf.obj ^
    "%WDK%\Lib\10.0.22621.0\km\x64\ndis.lib" ^
    "%WDK%\Lib\10.0.22621.0\km\x64\ntoskrnl.lib" ^
    "%WDK%\Lib\10.0.22621.0\km\x64\hal.lib"

signtool sign /v /s MY /n "Thor Security" /t http://timestamp.digicert.com thor_lwf.sys
