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
  Папка для CSV и итоговых списков (может быть на другом диске). По умолчанию — текущая.
.PARAMETER TempDir
  Папка для временной физической распаковки (используется редко, только при CLI-fallback). По умолчанию: $env:TEMP\ArchiveAudit.
.PARAMETER Threads
  Степень параллелизма. По умолчанию = числу логических ядер.
.PARAMETER PerFileTimeoutSec
  Таймаут на проверку одного архива (по умолчанию 1800 сек).
.PARAMETER Restart
  Очистить per-root state и начать заново (CSV и broken_latest/errors_latest — заново).
.PARAMETER Passwords
  Список паролей для проверки защищённых контейнеров (zip/7z/rar4).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
  [string[]]$Path,
  [string]$OutDir = (Get-Location).Path,
  [string]$TempDir = (Join-Path $env:TEMP "ArchiveAudit"),
  [int]$Threads = [Math]::Max(1, [Environment]::ProcessorCount),
  [int]$PerFileTimeoutSec = 1800,
  [switch]$Restart,
  [string[]]$Passwords
)

begin {
  $ErrorActionPreference = 'Stop'
  try { $PSStyle.OutputRendering = 'PlainText' } catch {}

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
  if (-not (Test-Path -LiteralPath $TempDir)) { New-Item -ItemType Directory -Force -Path $TempDir | Out-Null }

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
  if (-not (Test-Path -LiteralPath $csvPath)) { "TopPath,Status,Chain,Detail" | Out-File -FilePath $csvPath -Encoding UTF8 }
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
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
      if (-not $p.WaitForExit($timeoutSec*1000)) { try { $p.Kill($true) } catch {}; return @{ Exit=124; Err="7z timeout after $timeoutSec s" } }
      $err = $p.StandardError.ReadToEnd()
      return @{ Exit=$p.ExitCode; Err=$err }
    } finally { $p.Dispose() }
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
    try { Add-Content -Path $filePath -Value $line -Encoding UTF8 }
    finally { $mtx.ReleaseMutex() | Out-Null; $mtx.Dispose() }
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

  if ($targets.Count -eq 0) { Write-Host "Нечего делать: всё уже завершено или архивов нет." -ForegroundColor Green; return }

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

    # Резолвер зависимостей (если доступен)
    try {
      [System.Runtime.Loader.AssemblyLoadContext]::Default.add_Resolving({
        param($context, $name)
        if ([string]::IsNullOrEmpty($Script:REAsmDir)) { return $null }
        $candidate = Join-Path $Script:REAsmDir ($name.Name + '.dll')
        if (Test-Path $candidate) { return $context.LoadFromAssemblyPath($candidate) }
        return $null
      }) | Out-Null
    } catch {}

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
    $result = [ordered]@{ Status=""; Detail=""; BrokenChains=@() }
    if (-not $REAvailable) { $result.Status = "UNAVAILABLE"; $result.Detail = "Library not available"; return $result }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $top = $file
    $broken = New-Object System.Collections.Generic.List[string]

    function Set-Opt($obj, $name, $value) {
      $prop = $obj.GetType().GetProperty($name)
      if ($prop -and $prop.CanWrite) { $prop.SetValue($obj, $value) }
    }

    try {
      $ExtractorType = Get-REType "$RE_NS.Extractor"
      $OptionsType   = Get-REType "$RE_NS.ExtractorOptions"

      if (-not $ExtractorType) { throw "Extractor type not found in RecursiveExtractor assemblies." }

      $extractor = [Activator]::CreateInstance($ExtractorType)
      $opts = if ($OptionsType) { [Activator]::CreateInstance($OptionsType) } else { $null }
      if ($opts) {
        Set-Opt $opts 'ExtractSelfOnFail' $true

        # Корректная передача паролей: Dictionary<Regex, List[string]>
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

      foreach ($entry in $entries) {
        try {
          $stream = $entry.Content
          if ($null -eq $stream) { continue }
          $buf = New-Object byte[] 65536
          while (($read = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
            if ($sw.Elapsed.TotalSeconds -ge $timeoutSec) { throw [System.TimeoutException]::new("Timeout $timeoutSec s") }
          }
          $stream.Dispose()
        } catch {
          $full = $entry.FullPath
          if (-not $full) { $full = $top }
          if ($full -and -not $full.StartsWith($top, [StringComparison]::OrdinalIgnoreCase)) { $full = "$top!$full" }
          $msg = $_.Exception.Message -replace '[\r\n]+',' '
          $broken.Add("$full :: $msg")
        }
      }

      if ($broken.Count -gt 0) {
        $result.Status = "BROKEN"
        $result.BrokenChains = $broken.ToArray()
        $result.Detail = "Broken entries: " + $broken.Count
      } else {
        $result.Status = "OK"
      }
    }
    catch [System.OverflowException] {
      $result.Status = "BROKEN"
      $result.Detail = "Zip bomb / Quine detected: " + ($_.Exception.Message -replace '[\r\n]+',' ')
      $result.BrokenChains = @("$top :: ZipBomb/Quine")
    }
    catch [System.TimeoutException] {
      $result.Status = "TIMEOUT"
      $result.Detail = "Timeout $timeoutSec s"
    }
    catch {
      $result.Status = "ERROR"
      $result.Detail = $_.Exception.Message -replace '[\r\n]+',' '
    }
    finally { $sw.Stop() }

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

  # ---------- тело одной обработки ----------
  function Invoke-One([System.IO.FileInfo]$fi) {
    $topPath = $fi.FullName
    $root = Get-RootFor $topPath
    $stateFile = if ($root) { $rootState[$root] } else { $null }

    # 1) Основной тест
    $res = Test-ArchiveDeep-Lib -file $topPath -timeoutSec $PerFileTimeoutSec -pwds $Passwords
    $status = $res.Status
    $detail = $res.Detail
    $chains = @()
    if ($res.BrokenChains) { $chains = $res.BrokenChains }

    # 2) Fallback: 7z t
    if ( ($status -eq "ERROR" -or $status -eq "TIMEOUT" -or $status -eq "UNAVAILABLE") -and $Use7z ) {
      $to = [Math]::Min($PerFileTimeoutSec, 1200)           # ← исключаем парсерные косяки
      $z = Invoke-7zTest -exe $SevenZip -file $topPath -timeoutSec $to
      if ($z.Exit -eq 0) {
        $status = "OK"
        $detail = "verified via 7z (container)"
      } else {
        if ($status -ne "TIMEOUT") { $status = "BROKEN" }
        if ([string]::IsNullOrEmpty($detail)) { $detail = ($z.Err -replace '[\r\n]+',' ') }
        if (-not $chains -or $chains.Count -eq 0) { $chains = @("$topPath :: " + ($detail)) }
      }
    }

    # 3) CSV
    if ($status -eq "BROKEN" -and $chains.Count -gt 0) {
      foreach ($ch in $chains) {
        $line = ('"{0}","{1}","{2}","{3}"' -f (CsvEsc $topPath), 'BROKEN', (CsvEsc $ch), (CsvEsc $detail))
        Append-LineSafe -filePath $csvPath -line $line
      }
    } else {
      $line = ('"{0}","{1}","{2}","{3}"' -f (CsvEsc $topPath), (CsvEsc $status), "", (CsvEsc $detail))
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
        Append-LineSafe -filePath $brokenLatest -line $topPath
        Append-LineSafe -filePath $brokenAll    -line $topPath
      }
    }

    # 5) State
    if ($stateFile -and ($status -eq 'OK' -or $status -eq 'BROKEN')) {
      $line = ('{0}' + "`t" + '{1}' + "`t" + '{2}' + "`t" + '{3}') -f $status, $topPath, $fi.Length, $fi.LastWriteTimeUtc.ToString("o")
      Append-LineSafe -filePath $stateFile -line $line
    }

    if ($status -ne 'OK' -and $status -ne 'BROKEN') {
      $errDetail = if ([string]::IsNullOrEmpty($detail)) { $status } else { $detail }
      Append-LineSafe -filePath $errorsLatest -line ($topPath + "`t" + $errDetail)
    }
  }
}

process {}

end {
  Write-Host ("Найдено архивов к проверке: {0}" -f $targets.Count) -ForegroundColor Cyan

  $total = $targets.Count
  [int]$processed = 0
  $swAll = [System.Diagnostics.Stopwatch]::StartNew()

  if ($Threads -le 1 -or $total -le 1) {
    foreach ($fi in $targets) {
      Invoke-One -fi $fi
      $done = [System.Threading.Interlocked]::Increment([ref]$processed)
      if (($done % [Math]::Max(1, [int]($total/100))) -eq 0) { Show-Progress -done $done -all $total -elapsed $swAll.Elapsed }
    }
  } else {
    $po = [System.Threading.Tasks.ParallelOptions]::new()
    $po.MaxDegreeOfParallelism = $Threads

    $action = [System.Action[System.IO.FileInfo]]{
      param([System.IO.FileInfo]$fi)
      Invoke-One -fi $fi
      [System.Threading.Interlocked]::Increment([ref]$using:processed) | Out-Null
      if (($using:processed % [Math]::Max(5, [int]($using:total/100))) -eq 0) {
        Show-Progress -done $using:processed -all $using:total -elapsed $using:swAll.Elapsed
      }
    }

    $targetsEnum = [System.Collections.Generic.IEnumerable[System.IO.FileInfo]]$targets
    [System.Threading.Tasks.Parallel]::ForEach($targetsEnum, $po, $action)
  }

  $swAll.Stop()
  Write-Host ("Готово: {0} файлов, за {1:hh\:mm\:ss}. CSV: {2}" -f $total, $swAll.Elapsed, $csvPath) -ForegroundColor Green
  Write-Host ("State per-root: {0}" -f (($rootState.Values) -join '; '))
  Write-Host ("BROKEN (сессия): {0}" -f $brokenLatest)
  Write-Host ("BROKEN (кумулятив): {0}" -f $brokenAll)
  if (Test-Path $errorsLatest -PathType Leaf -ErrorAction SilentlyContinue) {
    if ((Get-Item $errorsLatest).Length -gt 0) {
      Write-Host ("Ошибки/таймауты (сессия): {0}" -f $errorsLatest) -ForegroundColor DarkYellow
    }
  }
}
