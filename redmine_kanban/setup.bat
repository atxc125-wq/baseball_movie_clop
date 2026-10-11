@echo off
rem Design task board: first-time setup (API key, auto start, desktop shortcut)
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 kanban_relay.py --setup
) else (
  python kanban_relay.py --setup
)
