@echo off
title ARACHNE OSINT
cd /d "%~dp0"
python server.py %*
if errorlevel 1 pause
