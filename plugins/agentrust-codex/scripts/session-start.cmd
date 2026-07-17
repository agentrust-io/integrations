@echo off
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 "%PLUGIN_ROOT%\engine\capture.py" hook
  exit /b 0
)

where python >nul 2>nul
if %errorlevel% equ 0 (
  python "%PLUGIN_ROOT%\engine\capture.py" hook
  exit /b 0
)

echo {"continue":true,"systemMessage":"AgenTrust: skipped the integrity check because Python is unavailable."}
exit /b 0
