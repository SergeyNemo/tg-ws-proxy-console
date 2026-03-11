@echo off
REM Build script for PyInstaller

echo ========================================
echo TG WS Proxy - Building EXE
echo ========================================

REM Check if PyInstaller is installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo.
echo Building executable...
pyinstaller build.spec

echo.
echo ========================================
echo Build complete! 
echo EXE file: dist\windows.exe
echo ========================================
echo.
pause
