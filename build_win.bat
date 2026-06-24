@echo off
setlocal enabledelayedexpansion

git submodule init
git submodule update

set OPENSSL_VERSION=openssl-1.1.1-gost-0.30
set OPENSSL_URL=https://github.com/deemru/openssl/releases/download/%OPENSSL_VERSION%/

curl -fsSL -o includes.zip %OPENSSL_URL%includes.zip || exit /b 1
curl -fsSL -o bin32.zip %OPENSSL_URL%bin32.zip || exit /b 1
curl -fsSL -o bin64.zip %OPENSSL_URL%bin64.zip || exit /b 1

7z x includes.zip -aoa
set OPENSSL_INCLUDE=.
if not exist %OPENSSL_INCLUDE%\ms mkdir %OPENSSL_INCLUDE%\ms
curl -fsSL -o %OPENSSL_INCLUDE%\ms\applink.c https://raw.githubusercontent.com/deemru/openssl/%OPENSSL_VERSION%/ms/applink.c || exit /b 1

set INCLUDES=/I%OPENSSL_INCLUDE% /I./src/msspi/third_party/cprocsp/include
set CFLAGS_CPP=/c /Ox /Os /GL /GF /GS- /Wall /EHa /DMSSPI_USE_MSSPI_CERT %INCLUDES%
set CFLAGS_C=/c /Ox /Os /GL /GF /GS- /W4 /DUSE_MSSPI /DMSSPI_USE_MSSPI_CERT %INCLUDES%
set LIBS=crypt32.lib advapi32.lib ws2_32.lib shell32.lib user32.lib gdi32.lib comdlg32.lib

set SRC_CPP=src/msspi/src/msspi.cpp
set SRC_C=src/client.c src/fd.c src/file.c src/libwrap.c src/log.c src/network.c src/options.c src/protocol.c src/pty.c src/resolver.c src/sthreads.c src/str.c src/stunnel.c src/tls.c src/ui_win_cli.c src/ui_win_gui.c
set OBJS=msspi.obj client.obj fd.obj file.obj libwrap.obj log.obj network.obj options.obj protocol.obj pty.obj resolver.obj sthreads.obj str.obj stunnel.obj tls.obj ui_win_gui.obj

for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS_PATH=%%i
if not defined VS_PATH (
    echo ERROR: Visual Studio not found
    exit /b 1
)
set VCVARSALL=%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat

rem ======================== x86 ========================
echo.
echo ========== Building x86 ==========
echo.

call "%VCVARSALL%" x86 || exit /b 1

7z x bin32.zip -aoa
copy /y bin32\opensslconf.h %OPENSSL_INCLUDE%\openssl\opensslconf.h >nul

cl %CFLAGS_CPP% %SRC_CPP% || exit /b 1
for %%f in (%SRC_C%) do (
    cl %CFLAGS_C% %%f || exit /b 1
)

pushd src
rc -r resources.rc || exit /b 1
popd

link /LTCG %OBJS% %LIBS% ./src/resources.res /subsystem:windows /OUT:stunnel-msspi.exe || exit /b 1

if defined BUILD_TAG (
    7z a %BUILD_TAG%-386-windows.zip stunnel-msspi.exe || exit /b 1
)

rem ======================== x64 ========================
echo.
echo ========== Building x64 ==========
echo.

call "%VCVARSALL%" x64 || exit /b 1

7z x bin64.zip -aoa
copy /y bin64\opensslconf.h %OPENSSL_INCLUDE%\openssl\opensslconf.h >nul

cl %CFLAGS_CPP% %SRC_CPP% || exit /b 1
for %%f in (%SRC_C%) do (
    cl %CFLAGS_C% %%f || exit /b 1
)

pushd src
rc -r resources.rc || exit /b 1
popd

link /LTCG %OBJS% %LIBS% ./src/resources.res /subsystem:windows /OUT:stunnel-msspi.exe || exit /b 1

if defined BUILD_TAG (
    7z a %BUILD_TAG%-amd64-windows.zip stunnel-msspi.exe || exit /b 1
)

echo.
echo ========== Build complete ==========
