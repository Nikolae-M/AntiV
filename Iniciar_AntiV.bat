@echo off
cd /d "%~dp0"
python -m antiv
if errorlevel 1 pause
