param(
    [string]$OutputDir = (Join-Path $PSScriptRoot '..\artifacts\run'),
    [switch]$RemoveSymbols
)

$ErrorActionPreference = 'Continue'

$removed = 0
if (Test-Path -LiteralPath $OutputDir) {
    Get-ChildItem -LiteralPath $OutputDir -File | Where-Object { $_.Name -like 'dumped-*' } | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Force
        $removed++
    }
}

$symbols = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'symbols'
if ($RemoveSymbols -and (Test-Path -LiteralPath $symbols)) {
    Remove-Item -LiteralPath $symbols -Recurse -Force
    $removed++
}

if (-not ('DumpDriver.Kernel32' -as [type])) {
    Add-Type -Namespace DumpDriver -Name Kernel32 -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern uint QueryDosDevice(string DeviceName, System.Text.StringBuilder TargetPath, uint Max);'
}

$buffer = New-Object System.Text.StringBuilder 65536
[void][DumpDriver.Kernel32]::QueryDosDevice($null, $buffer, 65536)
$links = @($buffer.ToString() -split "`0" | Where-Object { $_ -like 'Dmp_*' })
$service = Get-Service -Name iqvw64e -ErrorAction SilentlyContinue

if ($links.Count -gt 0) {
    Write-Output "[-] device links remain: $($links -join ', ')"
    exit 1
}
if ($service) {
    Write-Output "[-] carrier service remains: $($service.Name) $($service.Status)"
    exit 1
}

Write-Output "[+] rollback removed=$removed device_links=0 carrier_service=0"
exit 0
