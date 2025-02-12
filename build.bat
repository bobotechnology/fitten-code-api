@echo off
echo Building...
if exist api.exe del api.exe
pyinstaller --onefile api.py
xcopy dist\api.exe . /s /y /i
if exist dist rd /s /q dist
if exist build rd /s /q build
if exist api.spec del api.spec
echo Build complete.
pause