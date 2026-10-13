@echo off
title Server Health Manager

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ServerHealthManager.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Server Health Manager exited with an error.
    pause
)
