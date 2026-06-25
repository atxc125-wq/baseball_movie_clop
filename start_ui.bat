@echo off
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 (
    python -m baseball_clop.cli ui
) else (
    py -m baseball_clop.cli ui
)
pause
