param(
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Continue'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$release = Join-Path $root 'x64'
$out = Join-Path $release $Configuration
$artifacts = Join-Path $root 'artifacts'
$run = Join-Path $artifacts 'run'
$verification = Join-Path $artifacts 'verification.txt'
New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
$lines = New-Object System.Collections.Generic.List[string]
$failed = 0
$stepExit = 0

function Record {
    param([string]$Text)
    $script:lines.Add($Text)
    Write-Output $Text
}

function Step {
    param([string]$Name, [scriptblock]$Body)
    Record ''
    Record "PS> $Name"
    $script:stepExit = 0
    $output = @(& $Body 2>&1)
    foreach ($line in $output) { Record ([string]$line) }
    Record "exit=$script:stepExit"
    if ($script:stepExit -ne 0) { $script:failed++ }
}

function Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Record "verification start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Record "configuration=$Configuration"
Record "elevated=$(Admin)"

Step 'Remove-Item .\x64 -Recurse -Force (baseline)' {
    if (Test-Path -LiteralPath $script:release) {
        Remove-Item -LiteralPath $script:release -Recurse -Force
    }
    if (Test-Path (Join-Path $script:out 'Dumper.exe')) {
        $script:stepExit = 1
        Write-Output 'baseline failed: Dumper.exe still present'
    } else {
        Write-Output 'baseline: Dumper.exe absent'
    }
}

Step 'hash inputs' {
    $files = @(Get-ChildItem -LiteralPath (Join-Path $script:root 'src') -Recurse -File)
    $files += @(Get-Item -LiteralPath (Join-Path $script:root 'DumpDriver.sln'), (Join-Path $script:root 'build\Directory.Build.props'), (Join-Path $script:root 'generated\driver_blob.hxx'), (Join-Path $script:root '.gitmodules') -ErrorAction SilentlyContinue)
    foreach ($file in $files) {
        $digest = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        Write-Output "$($digest.Hash)  $($file.FullName.Substring($script:root.Length + 1))"
    }
}

$msbuild = @('C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe') |
    Where-Object { Test-Path $_ } | Select-Object -First 1

Step "msbuild DumpDriver.sln /m /p:Configuration=$Configuration /p:Platform=x64" {
    & $script:msbuild (Join-Path $script:root 'DumpDriver.sln') /m /nologo /v:m /p:"Configuration=$script:Configuration" /p:Platform=x64
    $script:stepExit = $LASTEXITCODE
}

Step 'BlobGen --verify Driver.sys driver_blob.hxx' {
    & (Join-Path $script:out 'BlobGen.exe') --verify (Join-Path $script:out 'Driver.sys') (Join-Path $script:root 'generated\driver_blob.hxx')
    $script:stepExit = $LASTEXITCODE
}

Step 'Tests.exe (full suite)' {
    & (Join-Path $script:out 'Tests.exe')
    $script:stepExit = $LASTEXITCODE
}

Step 'Tests.exe --suite integration' {
    & (Join-Path $script:out 'Tests.exe') --suite integration
    $script:stepExit = $LASTEXITCODE
}

$fixtureProbe = Join-Path $run 'fixture-probe.txt'
$targetPid = $null
if (Admin) {
    Record ''
    Record 'PS> live cycle: Fixture.exe -> Dumper.exe -> validation'
    $fixture = $null
    try {
        New-Item -ItemType Directory -Force -Path $script:run | Out-Null
        $fixture = Start-Process -FilePath (Join-Path $script:out 'Fixture.exe') -RedirectStandardOutput $fixtureProbe -WindowStyle Hidden -PassThru
        $probe = ''
        for ($i = 0; $i -lt 100; $i++) {
            Start-Sleep -Milliseconds 50
            if (Test-Path -LiteralPath $fixtureProbe) {
                $probe = [System.IO.File]::ReadAllText($fixtureProbe)
                if ($probe.Contains('[+] event=')) { break }
            }
        }
        foreach ($line in $probe -split "`r?`n") { Record $line }
        $pidLine = [regex]::Match($probe, '\[\+\] pid=(\d+)')
        if (-not $pidLine.Success) { throw 'fixture probe did not report pid' }
        $targetPid = $pidLine.Groups[1].Value

        $dumperLog = Join-Path $script:run 'dumper-run.txt'
        $dumper = Start-Process -FilePath (Join-Path $script:out 'Dumper.exe') -ArgumentList @('--no-pause', '--pid', $targetPid, '--output', $script:run) -RedirectStandardOutput $dumperLog -RedirectStandardError (Join-Path $script:run 'dumper-error.txt') -WindowStyle Hidden -PassThru -Wait
        foreach ($line in [System.IO.File]::ReadAllLines($dumperLog)) { Record $line }
        Record "dumper_exit=$($dumper.ExitCode)"
        if ($dumper.ExitCode -ne 0) { throw "Dumper.exe exited $($dumper.ExitCode)" }
        if (-not ([System.IO.File]::ReadAllText($dumperLog).Contains('[+] driver loaded'))) { throw 'driver loaded log missing' }

        $dump = @(Get-ChildItem -LiteralPath $script:run -Filter 'dumped-*.dmp')
        $manifest = @(Get-ChildItem -LiteralPath $script:run -Filter 'dumped-*.txt')
        if ($dump.Count -ne 1 -or $manifest.Count -ne 1) { throw 'expected exactly one dump and manifest pair' }
        Record "dump=$($dump[0].FullName) size=$($dump[0].Length)"
        $dumpText = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($dump[0].FullName))
        foreach ($marker in @('PRIVATE_READABLE_MARKER_ONE_01', 'PRIVATE_READABLE_MARKER_TWO_02', 'MAPPED_READABLE_MARKER_VALUE_03')) {
            if (-not $dumpText.Contains($marker)) { throw "dump missing marker $marker" }
            Record "marker=$marker found"
        }
        $manifestText = [System.IO.File]::ReadAllText($manifest[0].FullName)
        foreach ($token in @('eprocess=0x', 'sha256=', 'type=0x1000000', 'type=0x40000', 'protect=0x1 copied=0x0', 'protect=0x104 copied=0x0')) {
            if (-not $manifestText.Contains($token)) { throw "manifest missing $token" }
            Record "manifest token=$token found"
        }
        foreach ($key in @('\[\+\] image=0x', '\[\+\] mapped=0x', '\[\+\] private_one=0x', '\[\+\] private_two=0x', '\[\+\] guard=0x', '\[\+\] noaccess=0x')) {
            $address = [regex]::Match($probe, "$key([0-9a-f]+)").Groups[1].Value
            if (-not $address) { throw "probe missing $key" }
            if (-not $manifestText.Contains("base=0x$address")) { throw "manifest missing base=0x$address" }
            Record "manifest region base=0x$address found"
        }

        $dumpchk = $null
        $command = Get-Command dumpchk.exe -ErrorAction SilentlyContinue
        if ($command) {
            $dumpchk = $command.Source
        } else {
            $found = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dumpchk.exe' -ErrorAction SilentlyContinue
            if ($found) { $dumpchk = $found.FullName }
        }
        if ($dumpchk) {
            Record "dumpchk=$dumpchk"
            $chk = & $dumpchk $dump[0].FullName 2>&1
            Record "dumpchk_exit=$LASTEXITCODE"
            foreach ($line in @($chk)) { Record [string]$line }
            if ($LASTEXITCODE -ne 0) { throw 'dumpchk rejected the dump' }
        } else {
            Record 'dumpchk=unavailable (skipped)'
        }
    } catch {
        Record "[-] live cycle: $($_.Exception.Message)"
        $script:failed++
    } finally {
        if ($fixture) {
            if (-not $fixture.HasExited) {
                Start-Process -FilePath (Join-Path $script:out 'Fixture.exe') -ArgumentList @('--release', "$targetPid") -WindowStyle Hidden | Out-Null
                $fixture.WaitForExit(15000) | Out-Null
            }
        }
    }
} else {
    Record ''
    Record '[-] live cycle skipped: not elevated'
    $script:failed++
}

Step 'scripts\rollback.ps1 (first run)' {
    & (Join-Path $script:root 'scripts\rollback.ps1') -OutputDir $script:run
    $script:stepExit = $LASTEXITCODE
}

Step 'scripts\rollback.ps1 (idempotence)' {
    & (Join-Path $script:root 'scripts\rollback.ps1') -OutputDir $script:run
    $script:stepExit = $LASTEXITCODE
}

Step 'rebuild after rollback' {
    & $script:msbuild (Join-Path $script:root 'DumpDriver.sln') /m /nologo /v:m /p:"Configuration=$script:Configuration" /p:Platform=x64
    $script:stepExit = $LASTEXITCODE
}

Record ''
Record "verification end: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') failed_gates=$script:failed"
[System.IO.File]::WriteAllLines($verification, $lines)
if ($script:failed -eq 0) {
    exit 0
}
exit 1
