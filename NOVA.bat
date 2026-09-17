@echo off
REM Double-click launcher for the NOVA desktop app.
REM pythonw keeps the console window from appearing behind the UI.
cd /d "%~dp0"
start "" pythonw -m nova_osint.gui
