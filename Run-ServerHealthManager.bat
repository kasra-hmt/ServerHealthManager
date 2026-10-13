@echo off
title Server Health Manager

REM Launch the read-only health-check UI without overriding execution policy.
powershell.exe -NoProfile -File "%~dp0ServerHealthManager.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Server Health Manager exited with an error.
    pause
)
