<#
.SYNOPSIS
  Глубокая проверка целостности архивов и вложенных архивов (resume-safe).
.DESCRIPTION
  - Основной путь: .NET-библиотека Microsoft.CST.RecursiveExtractor — чтение всех потоков (без записи на диск),
    фиксация цепочки вложений через FileEntry.FullPath, ловля исключений → точное место поломки.
  - Fallback: 7z 't' (проверка контейнера), и/или CLI RecursiveExtractor (с -TempDir) — только при необходимости.
  - Надёжное возобновление: per-root state (.archive-audit.completed.tsv), учёт длины и mtime.
.PARAMETER Path
  Один или несколько корневых путей (папки и/или одиночные файлы).
.PARAMETER OutDir
  Folder for CSV and audit summaries (default: C:\\Users\\local.admin\\Documents\\audit).
.PARAMETER TempDir
  Folder for streaming temp extraction (SSD, high endurance). Default: T:\\ArchiveAudit.
.PARAMETER Threads
  Degree of parallelism. Default = 1 (single thread to protect RAM).
.PARAMETER PerFileTimeoutSec
  Таймаут на проверку одного архива (по умолчанию 1800 сек).
.PARAMETER MaxEntryInMemoryMB
  Ограничение объема для буферизации вложений в RAM (МБ). 0 = писать все во временный каталог.
.PARAMETER MemoryTrimThresholdMB
  Hard working-set cap triggering GC + EmptyWorkingSet. 0 = auto (percent-based).
.PARAMETER MinTempFreeSpaceGB
  Minimal free-space guard for TempDir (GB). 0 = disable guard.
.PARAMETER TempCleanupRetentionHours
  Cleanup horizon for leftover session_* folders in TempDir (hours). Default = 6.
.PARAMETER Restart
  Очистить per-root state и начать заново (CSV и broken_latest/errors_latest — заново).
.PARAMETER Passwords
  Список паролей для проверки защищённых контейнеров (zip/7z/rar4).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
  [string[]]$Path,
  [string]$OutDir = 'C:\Users\local.admin\Documents\audit',
  [string]$TempDir = (Join-Path 'T:\' "ArchiveAudit"),
  [int]$Threads = 1,
  [int]$PerFileTimeoutSec = 1800,
  [int]$MaxEntryInMemoryMB = 0,
  [int]$MemoryTrimThresholdMB = 0,
  [int]$MemoryTrimPercent = 55,
  [int]$MinTempFreeSpaceGB = 0,
  [int]$TempCleanupRetentionHours = 6,
  [switch]$Restart,
  [string[]]$Passwords
)



begin {
  try {
    $Script:OriginalTempEnv = $null
    $Script:TempSessionDir = $null
    $Script:ArchiveAuditCleanupInvoked = $false
    $Script:TempBaseDir = $null
    $Script:EntryMemoryCutoffBytes = 0
    $Script:EntryFileBufferSizeBytes = 65536
    $Script:MemoryTrimThresholdMB = [Math]::Max(0, $MemoryTrimThresholdMB)
    $Script:TotalRAM_MB = 0

    if ($Script:MemoryTrimThresholdMB -gt 0 -and -not ("ArchiveAudit.Native.WorkingSet" -as [type])) {
      Add-Type -Namespace ArchiveAudit.Native -Name WorkingSet -MemberDefinition @"
[global::System.Runtime.InteropServices.DllImport("psapi.dll")]
public static extern bool EmptyWorkingSet(global::System.IntPtr hProcess);
"@
    }

    if ($Script:MemoryTrimThresholdMB -gt 0 -and -not ("ArchiveAudit.Native.WsTuner" -as [type])) {
      Add-Type -Namespace ArchiveAudit.Native -Name WsTuner -MemberDefinition @"
[global::System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool SetProcessWorkingSetSize(global::System.IntPtr hProcess, int dwMinimumWorkingSetSize, int dwMaximumWorkingSetSize);
"@
    }

    $bytesPerMB = [int64](1MB)
    # Detect total physical RAM (MB)
    try {
      $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
      if ($cs -and $cs.TotalPhysicalMemory) { $Script:TotalRAM_MB = [int]([math]::Round($cs.TotalPhysicalMemory / 1MB)) }
    } catch {}
    if ($Script:TotalRAM_MB -le 0) {
      try { $Script:TotalRAM_MB = [int]([math]::Round((Get-ComputerInfo -ErrorAction Stop).CsTotalPhysicalMemory/1MB)) } catch {}
    }

    # Compute adaptive trim threshold (if MB not specified)
    if ($Script:MemoryTrimThresholdMB -le 0 -and $MemoryTrimPercent -gt 0 -and $Script:TotalRAM_MB -gt 0) {
      $pct = [math]::Min(90,[math]::Max(40,$MemoryTrimPercent))
      $Script:MemoryTrimThresholdMB = [int]([math]::Floor($Script:TotalRAM_MB * $pct / 100.0))
    }

    # Compute adaptive entry-in-RAM cutoff when -1 (auto)
    if ($MaxEntryInMemoryMB -lt 0) {
      if ($Script:TotalRAM_MB -ge 24576) { $MaxEntryInMemoryMB = 64 }
      elseif ($Script:TotalRAM_MB -ge 16384) { $MaxEntryInMemoryMB = 32 }
      else { $MaxEntryInMemoryMB = 8 }
    }
    if ($MaxEntryInMemoryMB -lt 0) {
      throw "MaxEntryInMemoryMB must be greater or equal to 0 (0 = always flush to TEMP)."
    }
    if ($MaxEntryInMemoryMB -le 0) {
      $Script:EntryMemoryCutoffBytes = 0
      Write-Host "Entry contents always buffered via TEMP (MemoryStreamCutoff=0)." -ForegroundColor DarkCyan
    }
    else {
      $calcBytes = [int64]$MaxEntryInMemoryMB * $bytesPerMB
      $maxAllowed = [int64][int]::MaxValue
      $limitedBytes = [System.Math]::Min($maxAllowed, $calcBytes)
      $Script:EntryMemoryCutoffBytes = [int]$limitedBytes
      $displayMb = [math]::Round($Script:EntryMemoryCutoffBytes / [double]$bytesPerMB, 2)
      Write-Host ("Keep entries <= {0} MB in RAM, larger -> TEMP." -f $displayMb) -ForegroundColor DarkCyan
    }
    $Script:BaselineEntryMemoryCutoffBytes = $Script:EntryMemoryCutoffBytes

    if ($Script:MemoryTrimThresholdMB -gt 0) {
      Write-Host ("Working-set guard: {0} MB (GC/EmptyWorkingSet when exceeded)." -f $Script:MemoryTrimThresholdMB) -ForegroundColor DarkCyan
    }
    else {
      Write-Host "MemoryTrimThresholdMB=0 -- working-set guard disabled." -ForegroundColor DarkCyan
    }

    function Invoke-ArchiveAuditCleanup {
      if ($Script:ArchiveAuditCleanupInvoked) { return }
      $Script:ArchiveAuditCleanupInvoked = $true

      if ($Script:OriginalTempEnv) {
        if ($Script:OriginalTempEnv.Contains('TEMP')) { $env:TEMP = $Script:OriginalTempEnv['TEMP'] }
        if ($Script:OriginalTempEnv.Contains('TMP'))  { $env:TMP  = $Script:OriginalTempEnv['TMP'] }
      }

      if ($Script:TempSessionDir -and (Test-Path -LiteralPath $Script:TempSessionDir)) {
        try {
          Remove-Item -LiteralPath $Script:TempSessionDir -Recurse -Force -ErrorAction Stop
        } catch {
          Write-Warning ("Не удалось удалить временную папку {0}: {1}" -f $Script:TempSessionDir, $_.Exception.Message)
        }
      }
    }

        function Invoke-MemoryRelief {
      param([int]$ThresholdMB)
      if ($ThresholdMB -le 0) { return }
      try {
        $proc = [System.Diagnostics.Process]::GetCurrentProcess()
        if (-not $proc) { return }
        $currentMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        if ($currentMB -lt $ThresholdMB) { return }
        Write-Host ("[mem] Working set {0} MB > {1} MB — trimming (GC + WorkingSet)." -f $currentMB, $ThresholdMB) -ForegroundColor DarkYellow
        if ($Script:EntryMemoryCutoffBytes -ne 0) {
          $Script:EntryMemoryCutoffBytes = 0
          Write-Host "Switched MemoryStreamCutoff to 0 (TEMP-only)." -ForegroundColor DarkYellow
        }
        [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = 'CompactOnce'
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        try { [ArchiveAudit.Native.WorkingSet]::EmptyWorkingSet($proc.Handle) | Out-Null } catch {}
        try { [ArchiveAudit.Native.WsTuner]::SetProcessWorkingSetSize($proc.Handle, -1, -1) | Out-Null } catch {}
        Start-Sleep -Milliseconds 25
      } catch {}
    }`r`n`r`n    function Remove-StaleSessionDirs {
      param(
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][int]$OlderThanHours
      )
      if ($OlderThanHours -le 0) { return }
      if (-not (Test-Path -LiteralPath $BaseDir -PathType Container)) { return }
      $cutoff = (Get-Date).AddHours(-[math]::Abs($OlderThanHours))
      Get-ChildItem -LiteralPath $BaseDir -Directory -Filter 'session_*' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object {
          try {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
            Write-Host ("Удалён устаревший TEMP: {0}" -f $_.FullName) -ForegroundColor DarkGray
          } catch {
            Write-Warning ("Не удалось удалить TEMP {0}: {1}" -f $_.FullName, $_.Exception.Message)
          }
        }
    }

    function Assert-TempFreeSpace {
      param(
        [Parameter(Mandatory)][string]$TargetPath,
        [Parameter(Mandatory)][int]$MinFreeGB,
        [switch]$ThrowOnLow
      )
      if ($MinFreeGB -le 0) { return }
      try {
        $full = [IO.Path]::GetFullPath($TargetPath)
        $root = [IO.Path]::GetPathRoot($full)
        $drive = [System.IO.DriveInfo]::new($root)
        $freeGB = [math]::Round($drive.AvailableFreeSpace / 1GB, 2)
        if ($freeGB -lt $MinFreeGB) {
          $msg = "TempDir free space is {0} GB (< {1} GB)." -f $freeGB, $MinFreeGB
          if ($ThrowOnLow) { throw $msg } else { Write-Warning $msg }
        }
      } catch {
        $msg = "Unable to evaluate TempDir free space: {0}" -f $_.Exception.Message
        if ($ThrowOnLow) { throw $msg } else { Write-Warning $msg }
      }
    }    $ErrorActionPreference = 'Stop'
    try { $PSStyle.OutputRendering = 'PlainText' } catch {}

    try {
      $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
      if ($currentProcess) {
        $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
      }
    } catch {}

  # Подсказка, если запущено в Windows PowerShell 5.1 (Desktop)
  try {
    if ($PSVersionTable.PSEdition -ne 'Core') {
      Write-Warning "Рекомендуется PowerShell 7+ (Core): Windows PowerShell 5.1 не загрузит .NET-библиотеку; будет использоваться fallback 7-Zip."
    }
  } catch {}

  # ---------- Форматы / многотомники ----------
  $supportedExt = @(
    '.zip','.7z','.rar',
    '.tar','.tgz','.tar.gz','.txz','.tar.xz','.tbz2','.tar.bz2',
    '.iso','.vhd','.vhdx','.vmdk','.wim','.deb','.ar','.dmg',
    '.gz','.bz2','.xz'
  )
  function Should-Include([IO.FileInfo]$fi) {
    $n = $fi.Name.ToLowerInvariant()
    $ext = $fi.Extension.ToLowerInvariant()
    $isSupported =
      $supportedExt -contains $ext -or
      $n.EndsWith('.tar.gz') -or $n.EndsWith('.tar.bz2') -or $n.EndsWith('.tar.xz')
    if (-not $isSupported) {
      if ($n -match '\.(7z|zip|rar)\.\d{3}$') { return $n.EndsWith('.001') } # split 7z/zip/rar: только .001
      return $false
    }
    # rar: r00/r01... — игнорируем; *.partNN.rar — только part1
    if ($ext -match '^\.r\d{2,3}$') { return $false }
    if ($n -match '\.part(\d+)\.rar$') { return ([int]$matches[1] -eq 1) }
    # zip split: .z01 и т.п. — игнорируем, тестируем сам .zip
    if ($ext -match '^\.z\d{2}$') { return $false }
    return $true
  }

  # ---------- Путь -> корень; per-root state ----------
  $roots = @()
  foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) { Write-Warning "Path not found: $p"; continue }
    $full = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $p).Path)
    $roots += $full.TrimEnd('\')
  }
  if ($roots.Count -eq 0) { throw "Нет валидных путей в -Path." }
  $roots = $roots | Sort-Object { $_.Length } -Descending -Unique

  if ($Threads -gt 1) {
    Write-Warning "Параллельная обработка временно отключена, сканирование продолжится последовательно."
    $Threads = 1
  }

  $rootState = @{} # root -> .archive-audit.completed.tsv
  foreach ($r in $roots) {
    if ([IO.Directory]::Exists($r)) {
      $rootState[$r] = Join-Path $r '.archive-audit.completed.tsv'
      continue
    }
    if ([IO.File]::Exists($r)) {
      $rootState[$r] = $null
      continue
    }
    # запасной путь: если Test-Path считает контейнером, но Should-Include говорит "архив"
    if (Test-Path -LiteralPath $r -PathType Container) {
      try {
        $item = Get-Item -LiteralPath $r -ErrorAction Stop
        if ($item -and -not $item.PSIsContainer) {
          $rootState[$r] = $null
          continue
        }
      } catch {}
      $rootState[$r] = Join-Path $r '.archive-audit.completed.tsv'
    } else {
      $rootState[$r] = $null
    }
  }

  if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
  if ([string]::IsNullOrWhiteSpace($TempDir)) { throw "TempDir must not be empty." }
  try {
    $TempDir = [IO.Path]::GetFullPath($TempDir)
  } catch {
    throw ("TempDir path invalid ({0}): {1}" -f $TempDir, $_.Exception.Message)
  }
  if (-not (Test-Path -LiteralPath $TempDir)) {
    try {
      [IO.Directory]::CreateDirectory($TempDir) | Out-Null
    } catch {
      throw ("Не удалось создать временную директорию {0}: {1}" -f $TempDir, $_.Exception.Message)
    }
  }`r`n  Assert-TempFreeSpace -TargetPath $TempDir -MinFreeGB $MinTempFreeSpaceGB -ThrowOnLow`r`n  $Script:TempBaseDir = $TempDir
  if ($TempCleanupRetentionHours -gt 0) {
    Remove-StaleSessionDirs -BaseDir $Script:TempBaseDir -OlderThanHours $TempCleanupRetentionHours
  }
  $Script:OriginalTempEnv = [ordered]@{ TEMP = $env:TEMP; TMP = $env:TMP }
  $Script:TempSessionDir = Join-Path $TempDir ("session_" + [Guid]::NewGuid().ToString("N"))
  try {
    [IO.Directory]::CreateDirectory($Script:TempSessionDir) | Out-Null
  } catch {
    throw ("Не удалось создать рабочую временную директорию {0}: {1}" -f $Script:TempSessionDir, $_.Exception.Message)
  }
  $env:TEMP = $Script:TempSessionDir
  $env:TMP  = $Script:TempSessionDir
  Write-Host ("Временная рабочая папка: {0}" -f $Script:TempSessionDir) -ForegroundColor DarkCyan

  $csvPath       = Join-Path $OutDir 'archive-audit.csv'
  $brokenLatest  = Join-Path $OutDir 'broken_latest.txt'
  $brokenAll     = Join-Path $OutDir 'broken_all.txt'
  $errorsLatest  = Join-Path $OutDir 'errors_latest.txt'

  if ($Restart) {
    foreach ($sf in $rootState.Values) {
      if ([string]::IsNullOrWhiteSpace($sf)) { continue }
      if (Test-Path -LiteralPath $sf) { Remove-Item -LiteralPath $sf -Force }
    }
    foreach ($f in @($csvPath,$brokenLatest,$errorsLatest)) {
      if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
    }
  }
  if (-not (Test-Path -LiteralPath $csvPath)) {
    $header = "Путь (topPath),Статус (status),Цепочка (chain),Описание (detail)"
    [System.IO.File]::WriteAllText($csvPath, $header + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($true))
  }
  if (Test-Path -LiteralPath $brokenLatest) { Remove-Item -LiteralPath $brokenLatest -Force }
  if (Test-Path -LiteralPath $errorsLatest) { Remove-Item -LiteralPath $errorsLatest -Force }
  if (-not (Test-Path -LiteralPath $brokenAll)) { New-Item -ItemType File -Path $brokenAll | Out-Null }

  # ---------- 7-Zip fallback ----------
  function Find-7z {
    $cmd = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @("$Env:ProgramFiles\7-Zip\7z.exe", "$Env:ProgramFiles(x86)\7-Zip\7z.exe")
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
  }
  $SevenZip = Find-7z
  $Use7z = [bool]$SevenZip
  if ($Use7z) { Write-Host "7-Zip: $SevenZip (fallback активен)" -ForegroundColor Cyan }
  else { Write-Host "7-Zip не найден — fallback будет ограничен." -ForegroundColor DarkYellow }

  function Invoke-7zTest([string]$exe, [string]$file, [int]$timeoutSec) {
    if (-not (Test-Path $exe)) { return @{ Exit = 127; Err = "7z not found" } }
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    # не глушим stderr, чтобы получить текст ошибки
    $psi.Arguments = "t `"$file`" -bso0 -bsp0"
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = $null
    try {
      $p = [System.Diagnostics.Process]::Start($psi)
      try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}
    } catch {
      $errMsg = $_.Exception.Message -replace '[\r\n]+', ' '
      return @{ Exit = 125; Err = "7z launch failed: $errMsg" }
    }
    try {
      if (-not $p.WaitForExit($timeoutSec*1000)) { try { $p.Kill($true) } catch {}; return @{ Exit=124; Err="7z timeout after $timeoutSec s" } }
      $err = $p.StandardError.ReadToEnd()
      return @{ Exit=$p.ExitCode; Err=$err }
    } finally {
      if ($p) { $p.Dispose() }
    }
  }

  # ---------- Безопасная дозапись (Mutex) ----------
  function Get-MD5Hex([string]$s) {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { ($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($s)) | ForEach-Object { $_.ToString("x2") }) -join '' } finally { $md5.Dispose() }
  }
  function Get-NamedMutex([string]$path) {
    $name = "ArchiveAudit_" + (Get-MD5Hex $path)    # локальный именованный mutex
    $createdNew = $false
    return [System.Threading.Mutex]::new($false, $name, [ref]$createdNew)
  }
  function Append-LineSafe([string]$filePath, [string]$line) {
    $mtx = Get-NamedMutex $filePath
    $mtx.WaitOne() | Out-Null
    try {
      $encoding = [System.Text.UTF8Encoding]::new($true) # keep UTF-8 with BOM for new files
      $writer = [System.IO.StreamWriter]::new($filePath, $true, $encoding)
      try { $writer.WriteLine($line) }
      finally { $writer.Dispose() }
    }
    finally {
      $mtx.ReleaseMutex() | Out-Null
      $mtx.Dispose()
    }
  }

  # ---------- per-root Completed Set ----------
  function Load-CompletedSet([string]$stateFile) {
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($stateFile)) { return $set }
    if (-not (Test-Path -LiteralPath $stateFile)) { return $set }
    try {
      Get-Content -LiteralPath $stateFile -Encoding UTF8 | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) { return }
        $parts = $_ -split "`t"
        if ($parts.Length -lt 4) { return }
        $status = $parts[0]; $p = $parts[1]; $lenStr = $parts[2]; $tsStr = $parts[3]
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }
        $fi = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
        if ($null -eq $fi) { return }
        $okLen = $false; $okTs = $false
        try { $okLen = ([int64]$lenStr -eq [int64]$fi.Length) } catch {}
        try { $okTs  = ([datetime]::Parse($tsStr).ToUniversalTime() -eq $fi.LastWriteTimeUtc) } catch {}
        if ($okLen -and $okTs) { $null = $set.Add($fi.FullName) }
      }
    } catch {
      Write-Warning ("Ошибка чтения state {0}: {1}" -f $stateFile, $_.Exception.Message)
    }
    return $set
  }

  # ---------- Определение корня для файла ----------
  function Get-RootFor([string]$fullPath) {
    foreach ($r in $roots) { if ($fullPath.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $r } }
    return $null
  }

  # ---------- Сканирование и фильтрация ----------
  $completedAll = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($r in $roots) { (Load-CompletedSet $rootState[$r]) | ForEach-Object { [void]$completedAll.Add($_) } }

  $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $targets = New-Object System.Collections.Generic.List[System.IO.FileInfo]
  foreach ($r in $roots) {
    if (Test-Path -LiteralPath $r -PathType Leaf) {
      $fi = Get-Item -LiteralPath $r
      if ($fi -and (Should-Include $fi) -and -not $completedAll.Contains($fi.FullName)) { if ($seen.Add($fi.FullName)) { $targets.Add($fi) } }
      continue
    }
    Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue |
      Where-Object { Should-Include $_ } |
      ForEach-Object {
        if (-not $completedAll.Contains($_.FullName)) {
          if ($seen.Add($_.FullName)) { $targets.Add($_) }
        }
      }
  }

  if ($targets.Count -eq 0) {
    Write-Host "Нет целей: файлов для проверки не найдено." -ForegroundColor Green
    Invoke-ArchiveAuditCleanup
    return
  }

  # ---------- Загрузка .NET-библиотеки RecursiveExtractor ----------
  $Script:RE_NS = $null
  $Script:REAsmDir = $null
  $Script:REPrimaryAssembly = $null

  function Get-REType([string]$typeFullName) {
    foreach ($asm in [AppDomain]::CurrentDomain.GetAssemblies()) {
      try {
        $t = $asm.GetType($typeFullName, $false, $true)
      } catch { $t = $null }
      if ($t) { return $t }
    }
    if ($Script:REPrimaryAssembly -ne $null) {
      try {
        return $Script:REPrimaryAssembly.GetType($typeFullName, $false, $true)
      } catch { return $null }
    }
    if ($Script:REAsmDir) {
      $dll = Join-Path $Script:REAsmDir 'RecursiveExtractor.dll'
      if (Test-Path $dll) {
        try {
          $Script:REPrimaryAssembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($dll)
          return $Script:REPrimaryAssembly.GetType($typeFullName, $false, $true)
        } catch { return $null }
      }
    }
    return $null
  }

  function Ensure-RELibrary {

    function Find-RE-Cands {
      $out = @()
      $dllNamePred = {
        $_.Name -like 'Microsoft.CST*.RecursiveExtractor.dll' -or
        $_.Name -ieq 'RecursiveExtractor.dll'
      }

      # 1) Уже в памяти?
      try { $null = [Microsoft.CST.RecursiveExtractor.Extractor]; $Script:RE_NS = 'Microsoft.CST.RecursiveExtractor'; return @() } catch {}
      try { $null = [Microsoft.CST.OpenSource.RecursiveExtractor.Extractor]; $Script:RE_NS = 'Microsoft.CST.OpenSource.RecursiveExtractor'; return @() } catch {}

      # 2) Рядом с глобальным tool'ом
      $toolExe = Join-Path $env:USERPROFILE ".dotnet\tools\recursiveextractor.exe"
      if (Test-Path $toolExe) {
        $toolDir = Split-Path -Parent $toolExe
        $out += Get-ChildItem -Path $toolDir -Recurse -File -ErrorAction SilentlyContinue |
          Where-Object $dllNamePred |
          Select-Object -ExpandProperty DirectoryName -Unique
      }

      # 3) store CLI
      $storeRoot = Join-Path $env:USERPROFILE ".dotnet\tools\.store\microsoft.cst.recursiveextractor.cli"
      if (Test-Path $storeRoot) {
        $out += Get-ChildItem -Path $storeRoot -Recurse -File -ErrorAction SilentlyContinue |
          Where-Object $dllNamePred |
          Select-Object -ExpandProperty DirectoryName -Unique
      }

      # 4) nuget пакеты
      foreach ($pkg in @("microsoft.cst.recursiveextractor","microsoft.cst.recursiveextractor.cli")) {
        $nugetRoot = Join-Path $env:USERPROFILE (".nuget\packages\{0}" -f $pkg)
        if (Test-Path $nugetRoot) {
          $out += Get-ChildItem -Path $nugetRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object $dllNamePred |
            Select-Object -ExpandProperty DirectoryName -Unique
        }
      }
      return $out | Select-Object -Unique
    }

    $cands = Find-RE-Cands
    if ($cands.Count -eq 0) {
      try {
        $list = (& dotnet tool list -g) 2>$null | Out-String
        if ($null -eq ($list | Select-String 'Microsoft.CST.RecursiveExtractor.Cli')) {
          Write-Host "Устанавливаю Microsoft.CST.RecursiveExtractor.Cli…" -ForegroundColor Yellow
          & dotnet tool install -g Microsoft.CST.RecursiveExtractor.Cli | Out-Null
        }
      } catch {
        Write-Warning "Не удалось установить dotnet-tool: $($_.Exception.Message)"
      }
      $cands = Find-RE-Cands
      if ($cands.Count -eq 0) { return $false }
    }

    $dir = ($cands | Sort-Object { $_.Length } -Descending | Select-Object -First 1)
    $Script:REAsmDir = $dir

    # Предзагрузка всех .dll
    Get-ChildItem -LiteralPath $dir -Filter *.dll -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        if (-not $Script:REPrimaryAssembly -and ($_.BaseName -eq 'RecursiveExtractor')) {
          $Script:REPrimaryAssembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($_.FullName)
        } else {
          [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($_.FullName) | Out-Null
        }
      } catch {
        try { [System.Reflection.Assembly]::LoadFrom($_.FullName) | Out-Null } catch {}
      }
    }

    # Проверим пространство имён
    $type = Get-REType 'Microsoft.CST.RecursiveExtractor.Extractor'
    if ($type) { $Script:RE_NS = 'Microsoft.CST.RecursiveExtractor'; return $true }
    $type = Get-REType 'Microsoft.CST.OpenSource.RecursiveExtractor.Extractor'
    if ($type) { $Script:RE_NS = 'Microsoft.CST.OpenSource.RecursiveExtractor'; return $true }
    return $false
  }

  $REAvailable = $false
  try { $REAvailable = Ensure-RELibrary } catch { $REAvailable = $false }
  if ($REAvailable) { Write-Host "RecursiveExtractor .NET библиотека загружена: $RE_NS (из $REAsmDir)" -ForegroundColor Cyan }
  else { Write-Host "Не удалось загрузить библиотеку RecursiveExtractor — будет больше fallback'ов." -ForegroundColor DarkYellow }

  # ---------- Проверка одной записи через библиотеку ----------
    function Test-ArchiveDeep-Lib([string]$file, [int]$timeoutSec, [string[]]$pwds) {
    $result = [ordered]@{ Status=""; Detail=""; BrokenChains=@(); BrokenItems=@() }
    if (-not $REAvailable) {
      $result.Status = "UNAVAILABLE"
      $result.Detail = "Библиотека RecursiveExtractor недоступна (unavailable)"
      return $result
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $top = $file
    $broken = New-Object System.Collections.Generic.List[object]

    function Set-Opt($obj, $name, $value) {
      $prop = $obj.GetType().GetProperty($name)
      if ($prop -and $prop.CanWrite) { $prop.SetValue($obj, $value) }
    }

    $extractor = $null
    $opts = $null
    $entries = $null
    $entriesEnumerator = $null
    $buffer = $null

    try {
      $ExtractorType = Get-REType "$RE_NS.Extractor"
      $OptionsType   = Get-REType "$RE_NS.ExtractorOptions"

      if (-not $ExtractorType) { throw "Extractor type not found in RecursiveExtractor assemblies." }

      $extractor = [Activator]::CreateInstance($ExtractorType)
      $opts = if ($OptionsType) { [Activator]::CreateInstance($OptionsType) } else { $null }
      if ($opts) {
        if ($Script:EntryMemoryCutoffBytes -ge 0) {
          Set-Opt $opts 'MemoryStreamCutoff' $Script:EntryMemoryCutoffBytes
        }
        if ($Script:EntryFileBufferSizeBytes -gt 0) {
          Set-Opt $opts 'FileStreamBufferSize' $Script:EntryFileBufferSizeBytes
        }
        Set-Opt $opts 'ExtractSelfOnFail' $true
        Set-Opt $opts 'Recurse' $true
        Set-Opt $opts 'Parallel' $false

        # ���४⭠� ��।�� ��஫��: Dictionary<Regex, List[string]>
        if ($pwds -and $pwds.Count -gt 0) {
          $DictType = [type]'System.Collections.Generic.Dictionary[System.Text.RegularExpressions.Regex,System.Collections.Generic.List[string]]'
          $ListType = [type]'System.Collections.Generic.List[string]'
          $pwdDict  = [Activator]::CreateInstance($DictType)
          $pwdList  = [Activator]::CreateInstance($ListType, @())
          foreach ($p in $pwds) { $null = $pwdList.Add($p) }
          $anyRegex = [System.Text.RegularExpressions.Regex]::new('.*')
          $pwdDict.Add($anyRegex, $pwdList)
          Set-Opt $opts 'Passwords' $pwdDict
        }
      }

      $entries = if ($opts) { $extractor.Extract($file, $opts) } else { $extractor.Extract($file) }

      function Format-EntryPath([object]$entryObj) {
        if ($null -eq $entryObj) { return $top }
        $path = $entryObj.FullPath
        if ([string]::IsNullOrWhiteSpace($path)) {
          if ($entryObj.PSObject.Properties['ParentPath'] -and $entryObj.ParentPath) {
            $path = $entryObj.ParentPath
          } elseif ($entryObj.Parent -and $entryObj.Parent.FullPath) {
            $path = $entryObj.Parent.FullPath
          } elseif ($entryObj.Name) {
            $path = $entryObj.Name
          }
        }
        if ([string]::IsNullOrWhiteSpace($path)) { $path = $top }
        if ($path.StartsWith($top, [StringComparison]::OrdinalIgnoreCase)) { return $path }
        return "$top!$path"
      }

      function Get-ErrorSummary([object]$err) {
        if ($null -eq $err) { return "Unknown error" }
        $parts = New-Object System.Collections.Generic.List[string]
        $ex = $null
        if ($err -is [System.Management.Automation.ErrorRecord]) {
          $ex = $err.Exception
        } elseif ($err -is [System.Exception]) {
          $ex = $err
        }
        while ($ex) {
          $msg = $ex.Message
          if (-not [string]::IsNullOrWhiteSpace($msg)) {
            $parts.Add(("{0}: {1}" -f $ex.GetType().Name, ($msg -replace '[\r\n]+',' ').Trim()))
          } else {
            $parts.Add($ex.GetType().Name)
          }
          $ex = $ex.InnerException
        }
        if ($err -is [System.Management.Automation.ErrorRecord]) {
          $fqid = $err.FullyQualifiedErrorId
          if (-not [string]::IsNullOrWhiteSpace($fqid)) {
            $parts.Add("FQID: $fqid")
          }
        }
        if ($parts.Count -eq 0) {
          $txt = ($err | Out-String).Trim()
          if ([string]::IsNullOrWhiteSpace($txt)) { return "Unknown error" }
          return ($txt -replace '[\r\n]+',' ')
        }
        return ($parts -join " | ")
      }

      $enumerableCandidate = $entries -as [System.Collections.IEnumerable]
      if ($enumerableCandidate -and -not ($entries -is [string])) {
        $entriesEnumerator = $enumerableCandidate.GetEnumerator()
      } elseif ($null -ne $entries) {
        $entriesEnumerator = (,@($entries)).GetEnumerator()
      } else {
        $entriesEnumerator = @().GetEnumerator()
      }

      $buffer = New-Object byte[] 65536

      $lastPath = $top
      $enumeratorError = $null
      try {
        while ($true) {
          $hasNext = $false
          try { $hasNext = $entriesEnumerator.MoveNext() }
          catch {
            $enumeratorError = $_
            break
          }
          if (-not $hasNext) { break }
          $entry = $entriesEnumerator.Current
          if ($null -eq $entry) { continue }
          $currentPath = Format-EntryPath $entry
          $lastPath = $currentPath
          if ($entry.EntryStatus -and $entry.EntryStatus -ne [Microsoft.CST.RecursiveExtractor.FileEntryStatus]::Default) {
            # Dispose skipped entry stream to release temp file handles
            $skipStream = $null
            try { $skipStream = $entry.Content } catch {}
            if ($skipStream) {
              try { $skipStream.Dispose() } catch {}
            }
            $entryStatusInfo = Get-EntryStatusReason ($entry.EntryStatus.ToString()) $currentPath
            $broken.Add((New-BrokenItem -Path $currentPath -ReasonKey $entryStatusInfo.Key -Message $entryStatusInfo.Message))
            continue
          }
          $stream = $null
          try {
            $stream = $entry.Content
            if ($null -eq $stream) { continue }
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
              if ($sw.Elapsed.TotalSeconds -ge $timeoutSec) { throw [System.TimeoutException]::new("Timeout $timeoutSec s") }
              Invoke-MemoryRelief -ThresholdMB $Script:MemoryTrimThresholdMB
            }
          } catch {
            $errorInfo = Get-LocalizedErrorInfo (Get-ErrorSummary $_)
            $broken.Add((New-BrokenItem -Path $currentPath -ReasonKey $errorInfo.Key -Message $errorInfo.Message))
          } finally {
            if ($stream) {
              try { $stream.Dispose() } catch {}
            }
          }
        }
      } finally {
        if ($entriesEnumerator -and ($entriesEnumerator -is [System.IDisposable])) {
          $entriesEnumerator.Dispose()
        }
        $entriesEnumerator = $null
      }
      if ($enumeratorError) {
        $enumeratorInfo = Get-LocalizedErrorInfo (Get-ErrorSummary $enumeratorError)
        $msg = 'Сбой перечисления вложений (fileEntry)'
        if ($enumeratorInfo.Key -ne 'fileEntry') {
          $msg += ": " + $enumeratorInfo.Message
        }
        $broken.Add((New-BrokenItem -Path $lastPath -ReasonKey 'fileEntry' -Message $msg))
      }

      if ($broken.Count -gt 0) {
        $items = $broken.ToArray()
        $result.Status = "BROKEN"
        $result.BrokenItems = $items
        $result.BrokenChains = $items | ForEach-Object { "{0} :: {1}" -f $_.Path, $_.Message }
        $result.Detail = Get-BrokenDetailSummary $items
      } else {
        $result.Status = "OK"
        $result.Detail = ""
      }
    }
    catch [System.OverflowException] {
      $result.Status = "BROKEN"
      $message = "Обнаружена zip-бомба (zipBomb)"
      if ($_.Exception -and $_.Exception.Message) {
        $message += ": " + ($_.Exception.Message -replace '[\r\n]+',' ').Trim()
      }
      $item = New-BrokenItem -Path $top -ReasonKey 'zipBomb' -Message $message
      $result.BrokenItems = @($item)
      $result.BrokenChains = @("{0} :: {1}" -f $item.Path, $item.Message)
      $result.Detail = $message
    }
    catch [System.TimeoutException] {
      $result.Status = "TIMEOUT"
      $result.Detail = "Превышено время ожидания $timeoutSec с (timeout)"
    }
    catch {
      $result.Status = "ERROR"
      $errorText = if ($_.Exception) { $_.Exception.Message } else { ($_ | Out-String) }
      $errorInfo = Get-LocalizedErrorInfo $errorText
      $result.Detail = $errorInfo.Message
    }
    finally {
      if ($entries -and ($entries -is [System.IDisposable])) {
        try { $entries.Dispose() } catch {}
      }
      if ($opts -and ($opts -is [System.IDisposable])) {
        try { $opts.Dispose() } catch {}
      }
      if ($extractor -and ($extractor -is [System.IDisposable])) {
        try { $extractor.Dispose() } catch {}
      }
      $entries = $null
      $opts = $null
      $extractor = $null
      $buffer = $null
      $sw.Stop()
    }

    return $result
  }
  # ---------- прогресс ----------
  function Show-Progress([int]$done, [int]$all, [TimeSpan]$elapsed) {
    if ($done -lt 1) { return }
    $pct = [math]::Round(100.0 * $done / $all, 2)
    $eps = $elapsed.TotalSeconds / [math]::Max(1, $done)
    $etaSec = [int][math]::Round($eps * ($all - $done))
    Write-Host ("[{0}%] {1}/{2} | ETA {3}s" -f $pct, $done, $all, $etaSec)
  }

  function CsvEsc([string]$s) { if ($null -eq $s) { return "" } return $s.Replace('"','""') }

  $Script:StatusLabels = @{
    OK           = 'Исправен (ok)'
    BROKEN       = 'Повреждён (broken)'
    ERROR        = 'Ошибка (error)'
    TIMEOUT      = 'Тайм-аут (timeout)'
    UNAVAILABLE  = 'Библиотека недоступна (unavailable)'
  }

  $Script:ErrorSummaryPatterns = @(
    @{ Pattern = 'Failed to locate the Zip Header'; Key = 'brokenZipHeader'; Message = 'Повреждённый заголовок ZIP (brokenZipHeader)' },
    @{ Pattern = 'does not contain a method named ''GetEnumerator'''; Key = 'fileEntry'; Message = 'Сбой перечисления вложений (fileEntry)' },
    @{ Pattern = 'System\.OutOfMemoryException'; Key = 'outOfMemory'; Message = 'Недостаточно памяти при проверке (outOfMemory)' }
  )

  function Get-LocalizedStatus([string]$status) {
    if ([string]::IsNullOrWhiteSpace($status)) { return "" }
    if ($Script:StatusLabels.ContainsKey($status)) { return $Script:StatusLabels[$status] }
    return ("{0} (raw)" -f $status)
  }

  function Test-IsTarLikePath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $low = $path.ToLowerInvariant()
    foreach ($suffix in @('.tar','.tar.gz','.tgz','.tar.bz2','.tbz2','.tar.xz','.txz')) {
      if ($low.EndsWith($suffix)) { return $true }
    }
    return $false
  }

  function Get-EntryStatusReason([string]$statusName, [string]$path) {
    if ([string]::IsNullOrWhiteSpace($statusName)) {
      return @{ Key = 'entryStatus'; Message = 'Неизвестный статус записи (entryStatus)' }
    }
    switch ($statusName) {
      'EncryptedArchive' { return @{ Key = 'encryptedArchive'; Message = 'Зашифрованный вложенный архив (encryptedArchive)' } }
      'FailedArchive' {
        if (Test-IsTarLikePath $path) {
          return @{ Key = 'failedTarArchive'; Message = 'Не удалось разобрать tar-архив (failedArchive)' }
        }
        return @{ Key = 'failedArchive'; Message = 'Ошибка разбора вложенного архива (failedArchive)' }
      }
      default { return @{ Key = 'entryStatus'; Message = ("Статус записи: {0} (entryStatus)" -f $statusName) } }
    }
  }

  function Get-LocalizedErrorInfo([string]$text) {
    $clean = ($text -replace '[\r\n]+',' ').Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { return @{ Key = 'unknownError'; Message = 'Неизвестная ошибка (unknownError)' } }
    foreach ($info in $Script:ErrorSummaryPatterns) {
      if ($clean -match $info.Pattern) { return @{ Key = $info.Key; Message = $info.Message } }
    }
    return @{ Key = 'error'; Message = ("Ошибка: {0} (error)" -f $clean) }
  }

  function New-BrokenItem {
    param(
      [Parameter(Mandatory)] [string]$Path,
      [Parameter(Mandatory)] [string]$ReasonKey,
      [Parameter(Mandatory)] [string]$Message
    )
    return [pscustomobject]@{
      Path      = $Path
      ReasonKey = $ReasonKey
      Message   = $Message
    }
  }

  function Get-BrokenDetailSummary([object[]]$items) {
    if (-not $items -or $items.Count -eq 0) { return "" }
    $groups = $items | Group-Object -Property ReasonKey
    if ($groups.Count -eq 1) {
      $g = $groups[0]
      $count = $g.Count
      switch ($g.Name) {
        'encryptedArchive' { return ("Зашифрованные вложения: {0} (encryptedArchive)" -f $count) }
        'failedArchive'    { return ("Не удалось проверить вложенные архивы: {0} (failedArchive)" -f $count) }
        'failedTarArchive' { return ("Не удалось разобрать tar-архивы: {0} (failedArchive)" -f $count) }
        'brokenZipHeader'  { return ("Повреждённые ZIP-заголовки: {0} (brokenZipHeader)" -f $count) }
        'fileEntry'        { return ("Сбой перечисления вложений: {0} (fileEntry)" -f $count) }
        'outOfMemory'      { return "Недостаточно памяти при проверке (outOfMemory)" }
        default            { return ("Обнаружены проблемные вложения: {0} ({1})" -f $count, $g.Name) }
      }
    }
    $total = $items.Count
    return ("Обнаружены проблемные вложения: {0} (brokenMixed)" -f $total)
  }

  # ---------- тело одной обработки ----------
  function Invoke-One([System.IO.FileInfo]$fi) {
    $topPath = $fi.FullName
    Write-Host ("-> {0}" -f $topPath)
    Assert-TempFreeSpace -TargetPath $Script:TempBaseDir -MinFreeGB $MinTempFreeSpaceGB -ThrowOnLow
    $root = Get-RootFor $topPath
    $stateFile = if ($root) { $rootState[$root] } else { $null }

    # 1) Основной тест
    $res = Test-ArchiveDeep-Lib -file $topPath -timeoutSec $PerFileTimeoutSec -pwds $Passwords
    $status = $res.Status
    $detail = $res.Detail
    $chains = @()
    if ($res.BrokenChains) { $chains = $res.BrokenChains }
    if ([string]::IsNullOrWhiteSpace($detail)) { $detail = "" }

    # 2) Fallback: 7z t
    if ( ($status -eq "ERROR" -or $status -eq "TIMEOUT" -or $status -eq "UNAVAILABLE") -and $Use7z ) {
      $to = [Math]::Min($PerFileTimeoutSec, 1200)           # limit 7z verification time
      $z = Invoke-7zTest -exe $SevenZip -file $topPath -timeoutSec $to
      if ($z.Exit -eq 0) {
        $status = "OK"
        $detail = "Проверено через 7-Zip (container)"
      } else {
        if ($status -ne "TIMEOUT") { $status = "BROKEN" }
        $rawErr = if ([string]::IsNullOrWhiteSpace($detail)) { ($z.Err -replace '[\r\n]+',' ') } else { $detail }
        $errInfo = Get-LocalizedErrorInfo $rawErr
        $detail = $errInfo.Message
        if (-not $chains -or $chains.Count -eq 0) { $chains = @("$topPath :: $detail") }
      }
    }

    # 3) CSV
    if ($chains.Count -gt 0) {
      $hash = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
      $dedup = New-Object System.Collections.Generic.List[string]
      foreach ($ch in $chains) { if ($hash.Add($ch)) { [void]$dedup.Add($ch) } }
      $chains = $dedup.ToArray()
    }
    $csvStatus = Get-LocalizedStatus $status
    $csvDetail = if ([string]::IsNullOrWhiteSpace($detail)) { "" } else { $detail }
    if ($status -eq "BROKEN" -and $chains.Count -gt 0) {
      foreach ($ch in $chains) {
        $line = ('"{0}","{1}","{2}","{3}"' -f (CsvEsc $topPath), (CsvEsc $csvStatus), (CsvEsc $ch), (CsvEsc $csvDetail))
        Append-LineSafe -filePath $csvPath -line $line
      }
    } else {
      $line = ('"{0}","{1}","{2}","{3}"' -f (CsvEsc $topPath), (CsvEsc $csvStatus), "", (CsvEsc $csvDetail))
      Append-LineSafe -filePath $csvPath -line $line
    }

    # 4) Итоговые списки
    if ($status -eq 'BROKEN') {
      if ($chains.Count -gt 0) {
        foreach ($ch in $chains) {
          Append-LineSafe -filePath $brokenLatest -line $ch
          Append-LineSafe -filePath $brokenAll    -line $ch
        }
      } else {
        $fallback = if ([string]::IsNullOrWhiteSpace($csvDetail)) { $csvStatus } else { $csvDetail }
        $brokenLine = ("{0} :: {1}" -f $topPath, $fallback)
        Append-LineSafe -filePath $brokenLatest -line $brokenLine
        Append-LineSafe -filePath $brokenAll    -line $brokenLine
      }
    }

    # 5) State
    if ($stateFile -and ($status -eq 'OK' -or $status -eq 'BROKEN')) {
      $line = ('{0}' + "`t" + '{1}' + "`t" + '{2}' + "`t" + '{3}') -f $status, $topPath, $fi.Length, $fi.LastWriteTimeUtc.ToString("o")
      Append-LineSafe -filePath $stateFile -line $line
    }

    if ($status -ne 'OK' -and $status -ne 'BROKEN') {
      $errStatus = $csvStatus
      $errDetail = if ([string]::IsNullOrWhiteSpace($csvDetail)) { $errStatus } else { "$errStatus :: $csvDetail" }
      Append-LineSafe -filePath $errorsLatest -line ($topPath + "`t" + $errDetail)
    }
  }
  } catch {
    Invoke-ArchiveAuditCleanup
    throw
  }
}

process {}

end {
  try {
    Write-Host ("Задач к проверке: {0}" -f $targets.Count) -ForegroundColor Cyan

    $total = $targets.Count
    [int]$processed = 0
    $swAll = [System.Diagnostics.Stopwatch]::StartNew()

    foreach ($fi in $targets) {
      Invoke-One -fi $fi
      $done = [System.Threading.Interlocked]::Increment([ref]$processed)
      if (($done % [Math]::Max(1, [int]($total/100))) -eq 0) { Show-Progress -done $done -all $total -elapsed $swAll.Elapsed }
      Invoke-MemoryRelief -ThresholdMB $Script:MemoryTrimThresholdMB
    }

    $swAll.Stop()
    $duration = $swAll.Elapsed.ToString("hh\:mm\:ss")
    Write-Host ("Итого: {0} архивов, за {1}. CSV: {2}" -f $total, $duration, $csvPath) -ForegroundColor Green
    Write-Host ("State per-root: {0}" -f (($rootState.Values) -join '; '))
    Write-Host ("BROKEN (последние): {0}" -f $brokenLatest)
    Write-Host ("BROKEN (все): {0}" -f $brokenAll)
    if (Test-Path $errorsLatest -PathType Leaf -ErrorAction SilentlyContinue) {
      if ((Get-Item $errorsLatest).Length -gt 0) {
        Write-Host ("Ошибки/таймауты (сессия): {0}" -f $errorsLatest) -ForegroundColor DarkYellow
      }
    }
  }
  finally {
    Invoke-MemoryRelief -ThresholdMB $Script:MemoryTrimThresholdMB
    Invoke-ArchiveAuditCleanup
  }
}





