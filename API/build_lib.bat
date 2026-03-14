@echo off
REM Build libKeyAuth.a for iOS - run from macOS with Xcode
REM On Windows: Use WSL or transfer to Mac and run build_lib.sh
REM Alternative: Use Xcode GUI - create static library target, add .mm sources
echo.
echo KeyAuth Static Library Build
echo ===========================
echo.
echo On Windows, you need macOS/Xcode to build iOS .a
echo Option 1: Copy API folder to Mac, run: ./build_lib.sh
echo Option 2: Create Xcode project with static library target
echo.
echo Files to include in lib:
echo   - PackageValidator.mm
echo   - SecureMap.mm
echo   - EncryptionHelper.mm
echo   - KeychainHelper.mm
echo.
echo Headers to ship: KeyAuth.h KeyAuthConfig.h PackageValidator.h SecureMap.h
echo.
pause
