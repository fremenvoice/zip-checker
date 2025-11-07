<#
Collects diagnostic data required to troubleshoot unexpected reboots while running zip-checker.ps1.
Creates a timestamped session folder plus optional zip archive with event logs and environment info.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:USERPROFILE\Desktop\zip-checker-diag",
    [int]$HoursBack = 24,
    [int]$MaxEvents = 200,
    [switch]$SkipArchive
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$sessionDir = Join-Path $OutputRoot "session_$timestamp"
$evtxDir = Join-Path $sessionDir 'evtx'

New-Item -ItemType Directory -Path $evtxDir -Force | Out-Null
Start-Transcript -Path (Join-Path $sessionDir 'collector.log') -Force

function Save-Text {
    param(
        [scriptblock]$ScriptBlock,
        [string]$Path
    )
    try {
        & $ScriptBlock | Out-File -FilePath $Path -Encoding UTF8
    } catch {
        "Failed: $($_.Exception.Message)" | Out-File -FilePath $Path -Encoding UTF8
    }
}

$since = (Get-Date).AddHours(-[math]::Abs($HoursBack))
$millis = [int64]([math]::Abs($HoursBack) * 3600 * 1000)

# Export EVTX snapshots for offline analysis
$filters = "*[System[TimeCreated[timediff(@SystemTime) <= $millis]]]"
try {
    & wevtutil epl System (Join-Path $evtxDir "system-last${HoursBack}h.evtx") "/q:$filters" /ow:true
    & wevtutil epl Application (Join-Path $evtxDir "application-last${HoursBack}h.evtx") "/q:$filters" /ow:true
} catch {
    "wevtutil export failed: $($_.Exception.Message)" |
        Out-File -FilePath (Join-Path $sessionDir 'wevtutil-error.txt') -Encoding UTF8
}

# Text snapshots of critical events
Save-Text {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 2; StartTime = $since } -MaxEvents $MaxEvents |
        Select-Object TimeCreated, Id, ProviderName, Message | Format-List
} (Join-Path $sessionDir 'system-errors.txt')

Save-Text {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 2; StartTime = $since } -MaxEvents $MaxEvents |
        Select-Object TimeCreated, Id, ProviderName, Message | Format-List
} (Join-Path $sessionDir 'application-errors.txt')

Save-Text {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power' } -MaxEvents 100 |
        Select-Object TimeCreated, Id, Message | Format-List
} (Join-Path $sessionDir 'kernel-power.txt')

$shutdownIds = @(41, 1074, 1076, 6005, 6006, 6008)
Save-Text {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $shutdownIds } -MaxEvents 200 |
        Sort-Object TimeCreated -Descending |
        Select-Object TimeCreated, Id, ProviderName, Message | Format-List
} (Join-Path $sessionDir 'shutdown-events.txt')

Save-Text {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001 } -MaxEvents 50 |
        Select-Object TimeCreated, Id, Message | Format-List
} (Join-Path $sessionDir 'bugcheck.txt')

# Environment snapshot to capture resource state
Save-Text {
    Get-ComputerInfo |
        Select-Object CsName, OsName, OsVersion, WindowsProductName, WindowsEditionId,
            OsHardwareAbstractionLayer, CsNumberOfLogicalProcessors, CsTotalPhysicalMemory, OsHotFixes
} (Join-Path $sessionDir 'computer-info.txt')

Save-Text {
    Get-Process | Sort-Object CPU -Descending |
        Select-Object -First 40 Name, Id, CPU, WorkingSet, StartTime -ErrorAction SilentlyContinue
} (Join-Path $sessionDir 'top-processes.txt')

Save-Text {
    Get-WmiObject Win32_LogicalDisk |
        Select-Object DeviceID, DriveType, FileSystem, Size, FreeSpace, VolumeName
} (Join-Path $sessionDir 'logical-disks.txt')

Save-Text {
    Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size
} (Join-Path $sessionDir 'volume-status.txt')

Save-Text {
    Get-ChildItem $env:TEMP -Force |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 100 FullName, Length, LastWriteTime
} (Join-Path $sessionDir 'tempdir-snapshot.txt')

Stop-Transcript | Out-Null

if (-not $SkipArchive) {
    $zipPath = Join-Path $OutputRoot ("zipchecker-diag-{0}.zip" -f $timestamp)
    Compress-Archive -Path $sessionDir -DestinationPath $zipPath -Force
    Write-Host "Diagnostic bundle: $zipPath"
} else {
    Write-Host "Diagnostic folder ready: $sessionDir"
}
