@echo off
REM Launch the P2-BACnet Bridge configurator GUI without a console window.
REM Uses pythonw.exe instead of python.exe so there's no extra console flash.
REM If pythonw isn't on PATH, falls back to python.

cd /d "%~dp0"

where /q pythonw
if errorlevel 1 goto fallback

start "" pythonw p2_bridge_launcher.py
goto end

:fallback
REM No pythonw — try python in a minimized console
start "" /min python p2_bridge_launcher.py

:end
