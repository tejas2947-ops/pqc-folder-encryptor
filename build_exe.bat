@echo off
REM ============================================================
REM  TTPSEC PQC Encryptor — Build standalone .exe for Windows
REM ============================================================
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo.
echo  ====================================================
echo   TTPSEC - PQC Encryptor - Build .exe
echo  ====================================================
echo   Directory: %CD%
echo.

if not exist "pqc_encryptor.py" (
    echo  ERROR: pqc_encryptor.py not found in %CD%
    pause
    exit /b 1
)

echo  [1/4] Installing dependencies...
python -m pip install -r requirements.txt --quiet
python -m pip install -r requirements-dev.txt --quiet
if errorlevel 1 (
    echo  ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo  [2/4] Verifying pqcrypto...
python -c "from pqcrypto.kem.ml_kem_768 import generate_keypair; print('  ML-KEM-768 OK')"
if errorlevel 1 (
    echo  ERROR: pqcrypto not working
    pause
    exit /b 1
)
python -c "from pqcrypto.sign.ml_dsa_65 import generate_keypair; print('  ML-DSA-65  OK')"
if errorlevel 1 (
    echo  ERROR: pqcrypto ML-DSA-65 not working
    pause
    exit /b 1
)

echo  [3/4] Building .exe with PyInstaller (1-2 min)...
echo.

python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "PQC-Encryptor" ^
    --hidden-import pqcrypto ^
    --hidden-import pqcrypto.kem.ml_kem_768 ^
    --hidden-import pqcrypto.sign.ml_dsa_65 ^
    --hidden-import argon2 ^
    --hidden-import argon2.low_level ^
    --clean ^
    --noconfirm ^
    pqc_encryptor.py

if errorlevel 1 (
    echo.
    echo  ERROR: PyInstaller failed.
    pause
    exit /b 1
)

echo.
echo  [4/4] Cleaning up...
rmdir /s /q "build" 2>nul
del /q "*.spec" 2>nul

echo.
echo  ====================================================
echo   DONE: dist\PQC-Encryptor.exe
echo  ====================================================
echo.
echo   File: %CD%\dist\PQC-Encryptor.exe
echo   Distribute this .exe - no installation required.
echo.
pause
