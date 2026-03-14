@echo off
echo ========================================
echo URL Security Scanner Installation
echo ========================================
echo.

echo Installing required packages...
pip install -r requirements.txt

echo.
echo ========================================
echo Installation Complete!
echo Run: python scanner_cli.py [URL]
echo Or: run.bat [URL]
echo ========================================
pause
