@echo off
setlocal EnableExtensions
chcp 65001 >nul

set "ROOT=%~dp0"
cd /d "%ROOT%"

if not exist build mkdir build

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" goto VSWHERE_OK
set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" goto VSWHERE_OK

echo [ERROR] vswhere.exe introuvable.
echo Installe Visual Studio 2022 Build Tools avec le workload C++.
echo Commande possible:
echo   winget install --id Microsoft.VisualStudio.2022.BuildTools -e
exit /b 1

:VSWHERE_OK
echo [INFO] vswhere: %VSWHERE%

set "VSINSTALL="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"

if defined VSINSTALL goto VSINSTALL_OK
echo [ERROR] Visual Studio 2022 C++ Build Tools introuvable ou workload C++ absent.
echo Ouvre Visual Studio Installer et coche: Desktop development with C++.
exit /b 1

:VSINSTALL_OK
set "VCVARS=%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto VCVARS_OK
echo [ERROR] vcvars64.bat introuvable:
echo %VCVARS%
exit /b 1

:VCVARS_OK
echo [INFO] Visual Studio path: %VSINSTALL%
call "%VCVARS%"
if errorlevel 1 exit /b 1

set "VCPKG_X64=C:\Windows\System32\vcpkg\installed\x64-windows"
if not exist "%VCPKG_X64%\include\capstone\capstone.h" (
  echo [ERROR] Header Capstone introuvable:
  echo   %VCPKG_X64%\include\capstone\capstone.h
  echo Installe Capstone x64 dans ce vcpkg ou adapte VCPKG_X64 dans build_vs2022.bat.
  exit /b 1
)
if not exist "%VCPKG_X64%\lib\capstone.lib" (
  echo [ERROR] capstone.lib introuvable:
  echo   %VCPKG_X64%\lib\capstone.lib
  exit /b 1
)
if not exist "%VCPKG_X64%\bin\capstone.dll" (
  echo [ERROR] capstone.dll introuvable:
  echo   %VCPKG_X64%\bin\capstone.dll
  echo Important: ZennComp doit utiliser la DLL Capstone du meme vcpkg que capstone.lib, sinon les mnemoniques ASM seront corrompues.
  exit /b 1
)

echo [1/3] Compilation resources + icon...
rc.exe /nologo /i resources /fo build\ZennComp.res resources\ZennComp.rc
if errorlevel 1 goto RC_FAIL

echo [2/3] Compilation C++ Win32 GUI x64...
cl.exe /nologo /std:c++17 /EHa /O2 /W3 /utf-8 /DUNICODE /D_UNICODE /Iresources /Isrc /I "%VCPKG_X64%\include" src\main.cpp build\ZennComp.res /link /OUT:build\ZennComp.exe /SUBSYSTEM:WINDOWS /MANIFEST:NO /LIBPATH:"%VCPKG_X64%\lib" user32.lib gdi32.lib comdlg32.lib comctl32.lib shell32.lib advapi32.lib psapi.lib ole32.lib capstone.lib
if errorlevel 1 goto CL_FAIL

echo [3/3] Copie DLL runtime Capstone coherente...
copy /Y "%VCPKG_X64%\bin\capstone.dll" "build\capstone.dll" >nul
if errorlevel 1 goto DLL_FAIL
copy /Y "%VCPKG_X64%\bin\capstone.dll" "capstone.dll" >nul
if errorlevel 1 goto DLL_FAIL
if exist upx.exe copy /Y upx.exe build\upx.exe >nul

echo.
echo [OK] Build termine: build\ZennComp.exe
echo [OK] DLL Capstone synchronisee depuis: %VCPKG_X64%\bin\capstone.dll
echo Lance: .\build\ZennComp.exe
exit /b 0

:RC_FAIL
echo [ERROR] rc.exe failed.
exit /b 1

:CL_FAIL
echo [ERROR] Compilation failed.
exit /b 1

:DLL_FAIL
echo [ERROR] Copie de capstone.dll echouee.
exit /b 1
