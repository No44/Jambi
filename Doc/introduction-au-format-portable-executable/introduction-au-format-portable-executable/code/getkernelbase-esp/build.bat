@echo off

set NAME=getkernelbase-esp

if exist %NAME%.obj del %NAME%.obj
if exist %NAME%.exe del %NAME%.exe

\masm32\bin\ml /c /coff /nologo %NAME%.asm
\masm32\bin\link /SUBSYSTEM:CONSOLE %NAME%.obj > nul

dir %NAME%.*

pause
