@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

if not "%1"=="" (
    python scanner_cli.py %*
    goto :eof
)

:loop
cls
echo ========================================
echo URL 보안 스캐너
echo ========================================
echo.
set /p url="URL 입력 (종료하려면 'exit' 입력): "

if /i "!url!"=="exit" goto :eof
if "!url!"=="" goto :loop

python scanner_cli.py !url!
echo.
echo ========================================
echo 다른 URL을 스캔하려면 Enter를 누르세요...
echo ========================================
pause >nul
goto :loop
