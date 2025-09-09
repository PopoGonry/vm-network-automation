@echo off
chcp 65001 >nul
echo ================================================
echo     VM 네트워크 자동화 도구 - 빌드
echo ================================================
echo.

echo Python 환경을 확인합니다...
python --version
if %errorlevel% neq 0 (
    echo Python이 설치되지 않았거나 PATH에 등록되지 않았습니다.
    pause
    exit /b 1
)

echo.
echo 빌드 스크립트를 실행합니다...
python utils/build.py
if %errorlevel% neq 0 (
    echo 빌드에 실패했습니다.
    pause
    exit /b 1
)

pause
