@echo off
setlocal

echo ==========================================
echo   Secure Password Manager - Setup
echo ==========================================
echo.

echo [1/5] Checking Python installation...
python --version

if errorlevel 1 (
    echo.
    echo ERROR: Python is not installed or not available in PATH.
    echo Please install Python and try again.
    pause
    exit /b 1
)

echo.
echo [2/5] Creating virtual environment...

if exist venv (
    echo Virtual environment already exists.
) else (
    python -m venv venv

    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo.
echo [3/5] Activating virtual environment...

call venv\Scripts\activate.bat

if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment.
    pause
    exit /b 1
)

echo.
echo [4/5] Installing required packages...

python -m pip install --upgrade pip

if errorlevel 1 (
    echo ERROR: Failed to upgrade pip.
    pause
    exit /b 1
)

pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install requirements.
    pause
    exit /b 1
)

echo.
echo [5/5] Creating required directories...

if not exist instance mkdir instance

echo.
echo ==========================================
echo   Setup completed successfully!
echo ==========================================
echo.
echo To start the application:
echo.
echo     venv\Scripts\activate
echo     python app.py
echo.
echo Then open:
echo     http://127.0.0.1:5000
echo.

pause