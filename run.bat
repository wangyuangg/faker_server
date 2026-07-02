@echo off
cd /d "%~dp0"

if not exist ".venv" (
    echo Creating virtual environment...
    uv venv
)

echo Syncing dependencies...
uv sync

echo Starting Fake Server...
uv run python fake_server_hijack.py
pause
