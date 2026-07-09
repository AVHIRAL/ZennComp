param(
    [ValidateSet('VS2022','MinGW64')]
    [string]$Toolchain = 'VS2022'
)

Set-Location -LiteralPath $PSScriptRoot

if ($Toolchain -eq 'VS2022') {
    cmd /c .\build_vs2022.bat
    exit $LASTEXITCODE
}

cmd /c .\build_mingw64.bat
exit $LASTEXITCODE
