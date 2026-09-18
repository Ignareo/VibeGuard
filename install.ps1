# VibeGuard installer script (bilingual strings; comments in English)
#
# Features:
# - Install vibeguard.exe (prefer GitHub Release; fallback to build from source or go install)
# - Choose variant (lite/full): full includes SQLite audit persistence (larger)
# - Export ("download") the CA certificate to a file
# - Optional: install CA into trust store (system/user/auto/skip)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\\install.ps1

param(
  [string]$InstallDir = (Join-Path $HOME ".local\\bin"),
  [ValidateSet("auto", "lite", "full")]
  [string]$Variant = "auto",
  # Release tag to install, e.g. v0.2.0; default latest
  [string]$Version = "latest",
  [ValidateSet("system", "user", "auto", "skip")]
  [string]$Trust = "system",
  [ValidateSet("auto", "user", "skip")]
  [string]$PathMode = "auto",
  [ValidateSet("auto", "add", "skip")]
  [string]$AutostartMode = "auto",
  [ValidateSet("auto", "zh", "en")]
  [string]$Language = "auto",
  [switch]$Export,
  [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Common issue in Windows PowerShell: default TLS may be too old for GitHub
try {
  if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  }
} catch {
  # ignore
}

$ScriptLang = $null
$ScriptVariant = $null

function NormalizeLang([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $v = $Value.Trim().ToLowerInvariant()
  switch ($v) {
    "zh" { return "zh" }
    "zh-cn" { return "zh" }
    "zh_cn" { return "zh" }
    "cn" { return "zh" }
    "chinese" { return "zh" }
    "中文" { return "zh" }
    "en" { return "en" }
    "en-us" { return "en" }
    "en_us" { return "en" }
    "english" { return "en" }
    default {
      if ($v -match '^zh') { return "zh" }
      if ($v -match '^en') { return "en" }
      return $null
    }
  }
}

function DetectDefaultLang() {
  try {
    $name = [System.Globalization.CultureInfo]::CurrentUICulture.Name
    if ($name -match '^zh') { return "zh" }
  } catch {
    # ignore
  }
  return "en"
}

function NormalizeVariant([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $v = $Value.Trim().ToLowerInvariant()
  switch ($v) {
    "lite" { return "lite" }
    "full" { return "full" }
    default { return $null }
  }
}

if ($Language -ne "auto") { $ScriptLang = NormalizeLang $Language }
if (-not $ScriptLang) { $ScriptLang = NormalizeLang $env:VIBEGUARD_LANG }
if (-not $ScriptLang) { $ScriptLang = DetectDefaultLang }

if ($Variant -ne "auto") { $ScriptVariant = NormalizeVariant $Variant }
if (-not $ScriptVariant) { $ScriptVariant = NormalizeVariant $env:VIBEGUARD_VARIANT }

$canPromptAny = (-not $NonInteractive) -and (-not [Console]::IsInputRedirected) -and (-not [Console]::IsOutputRedirected)
if ($canPromptAny -and ($Language -eq "auto")) {
  Write-Host ""
  Write-Host "请选择语言 / Choose language:"
  Write-Host "  1) 中文"
  Write-Host "  2) English"
  $defaultChoice = if ($ScriptLang -eq "zh") { "1" } else { "2" }
  $prompt = if ($ScriptLang -eq "zh") { "选择 [$defaultChoice]" } else { "Choose [$defaultChoice]" }
  $choice = Read-Host $prompt
  if ([string]::IsNullOrWhiteSpace($choice)) { $choice = $defaultChoice }
  switch ($choice) {
    "1" { $ScriptLang = "zh" }
    "2" { $ScriptLang = "en" }
    default { }
  }
}

function T([string]$Zh, [string]$En) {
  if ($ScriptLang -eq "zh") { return $Zh }
  return $En
}

# Variant hint: default is lite (smaller); full includes SQLite audit persistence.
if (-not $ScriptVariant) {
  if ($canPromptAny -and ($Variant -eq "auto")) {
    Write-Host ""
    Write-Host (T "请选择安装变体（默认 lite，更轻量）：" "Choose install variant (default lite, smaller):")
    Write-Host (T "  1) lite  - 不含 SQLite 审计落盘（推荐）" "  1) lite  - No SQLite audit persistence (recommended)")
    Write-Host (T "  2) full  - 含 SQLite 审计落盘（体积更大）" "  2) full  - With SQLite audit persistence (larger)")
    $choice = Read-Host (T "选择 [1]" "Choose [1]")
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }
    if ($choice -eq "2") { $ScriptVariant = "full" } else { $ScriptVariant = "lite" }
  } else {
    $ScriptVariant = "lite"
  }
}

# Pass to vibeguard child processes (e.g. future multilingual init/trust prompts).
$env:VIBEGUARD_LANG = $ScriptLang
$env:VIBEGUARD_VARIANT = $ScriptVariant

# Persist selected language (used as default by admin UI and uninstall script).
try {
  $cfgDir0 = Join-Path $HOME ".vibeguard"
  New-Item -ItemType Directory -Force -Path "$cfgDir0" | Out-Null
  $langFile = Join-Path "$cfgDir0" "lang"
  [System.IO.File]::WriteAllText("$langFile", ($ScriptLang + "`n"), [System.Text.UTF8Encoding]::new($false))
} catch {
  # ignore
}

function Say([string]$Zh, [string]$En) {
  Write-Host ""
  Write-Host "==> $(T $Zh $En)"
}

function Die([string]$Zh, [string]$En) {
  Write-Host ""
  Write-Error (T ("错误：" + $Zh) ("Error: " + $En))
  exit 1
}

function Have([string]$Name) {
  return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Need([string]$Name) {
  if (-not (Have $Name)) {
    Die "缺少依赖：$Name" "Missing dependency: $Name"
  }
}

function InRepo() {
  return (Test-Path -LiteralPath "go.mod") -and (Test-Path -LiteralPath "cmd/vibeguard/main.go")
}

function Run([string]$File, [string[]]$Args) {
  & $File @Args
  if ($LASTEXITCODE -ne 0) {
    Die "命令执行失败：$File $($Args -join ' ')" "Command failed: $File $($Args -join ' ')"
  }
}

function DetectGoArch() {
  $a = $env:PROCESSOR_ARCHITEW6432
  if ([string]::IsNullOrWhiteSpace($a)) { $a = $env:PROCESSOR_ARCHITECTURE }
  if ([string]::IsNullOrWhiteSpace($a)) { return $null }
  $a = $a.Trim().ToUpperInvariant()
  switch ($a) {
    "AMD64" { return "amd64" }
    "ARM64" { return "arm64" }
    default { return $null }
  }
}

function DownloadFile([string]$Url, [string]$OutFile) {
  $headers = @{
    "User-Agent" = "VibeGuard-Installer"
  }
  if ($PSVersionTable.PSVersion.Major -lt 6) {
    Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri "$Url" -OutFile "$OutFile"
  } else {
    Invoke-WebRequest -Headers $headers -Uri "$Url" -OutFile "$OutFile"
  }
}

function GetExpectedSha256([string]$ChecksumsFile, [string]$AssetName) {
  if (-not (Test-Path -LiteralPath "$ChecksumsFile")) { return $null }
  $lines = Get-Content -LiteralPath "$ChecksumsFile" -ErrorAction Stop
  foreach ($line in $lines) {
    if ($line -match '^(?<hash>[a-fA-F0-9]{64})\s+\*?(?<file>.+)$') {
      $h = $Matches["hash"].ToLowerInvariant()
      $f = $Matches["file"].Trim()
      if ($f -eq "$AssetName") { return $h }
    }
  }
  return $null
}

function InstallFromRelease([string]$InstallDir0, [string]$Variant0, [string]$Version0) {
  $repo = $env:VG_INSTALL_REPO
  if ([string]::IsNullOrWhiteSpace($repo)) { $repo = "Ignareo/VibeGuard" }

  $goarch = DetectGoArch
  if (-not $goarch) {
    throw (T ("不支持的 Windows 架构：$($env:PROCESSOR_ARCHITECTURE)") ("Unsupported Windows architecture: $($env:PROCESSOR_ARCHITECTURE)"))
  }

  $suffix = ""
  if ($Variant0 -eq "full") { $suffix = "_full" }
  $asset = "vibeguard_windows_${goarch}${suffix}.zip"

  $base = $null
  if ([string]::IsNullOrWhiteSpace($Version0) -or $Version0 -eq "latest") {
    $base = "https://github.com/$repo/releases/latest/download"
  } else {
    $base = "https://github.com/$repo/releases/download/$Version0"
  }

  $tmpZip = Join-Path $env:TEMP ("vibeguard-" + [Guid]::NewGuid().ToString("N") + ".zip")
  $tmpSum = Join-Path $env:TEMP ("vibeguard-" + [Guid]::NewGuid().ToString("N") + ".checksums.txt")
  $tmpDir = Join-Path $env:TEMP ("vibeguard-" + [Guid]::NewGuid().ToString("N"))

  New-Item -ItemType Directory -Force -Path "$tmpDir" | Out-Null
  try {
    Say "从 Release 下载：$asset" "Downloading from Release: $asset"
    DownloadFile "$base/$asset" "$tmpZip"
    try {
      DownloadFile "$base/checksums.txt" "$tmpSum"
      $expected = GetExpectedSha256 "$tmpSum" "$asset"
      if ($expected) {
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath "$tmpZip").Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
          Die "校验失败：$asset SHA256 不匹配" "Checksum mismatch: $asset SHA256 does not match"
        }
      } else {
        Write-Warning (T "未在 checksums.txt 中找到对应条目：跳过校验" "Entry not found in checksums.txt: skipping verification")
      }
    } catch {
      Write-Warning (T ("下载/解析 checksums.txt 失败：跳过校验（" + $_.Exception.Message + "）") ("Failed to fetch/parse checksums.txt: skipping verification (" + $_.Exception.Message + ")"))
    }

    Expand-Archive -LiteralPath "$tmpZip" -DestinationPath "$tmpDir" -Force
    $exe = Join-Path "$tmpDir" "vibeguard.exe"
    if (-not (Test-Path -LiteralPath "$exe")) {
      throw (T "Release 包不包含 vibeguard.exe" "Release archive does not contain vibeguard.exe")
    }
    Copy-Item -Force -LiteralPath "$exe" -Destination (Join-Path "$InstallDir0" "vibeguard.exe")
    try { Unblock-File -LiteralPath (Join-Path "$InstallDir0" "vibeguard.exe") -ErrorAction SilentlyContinue | Out-Null } catch { }
  } finally {
    Remove-Item -Force -LiteralPath "$tmpZip" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Force -LiteralPath "$tmpSum" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Recurse -Force -LiteralPath "$tmpDir" -ErrorAction SilentlyContinue | Out-Null
  }
}

function IsAdmin() {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function PathContains([string]$PathValue, [string]$Dir) {
  if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
  if ([string]::IsNullOrWhiteSpace($PathValue)) { return $false }
  $parts = $PathValue -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  foreach ($p in $parts) {
    if ($p.Equals($Dir, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}

function EnsureUserPath([string]$Dir) {
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (-not (PathContains $userPath $Dir)) {
    $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) { "$Dir" } else { "$Dir;$userPath" }
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    return $true
  }
  return $false
}

function GetListenFromConfig([string]$Path) {
  if (-not (Test-Path -LiteralPath "$Path")) { return $null }
  try {
    $lines = Get-Content -LiteralPath "$Path" -ErrorAction Stop
  } catch {
    return $null
  }

  $inProxy = $false
  foreach ($line in $lines) {
    if ($line -match '^\s*proxy:\s*(#.*)?$') {
      $inProxy = $true
      continue
    }
    if ($inProxy -and $line -match '^[A-Za-z_][A-Za-z0-9_]*:\s*(#.*)?$') {
      $inProxy = $false
    }
    if ($inProxy -and $line -match '^\s*listen:\s*(.+)$') {
      $v = $Matches[1]
      $v = ($v -replace '\s+#.*$', '').Trim()
      $v = $v.Trim('"').Trim("'")
      if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
      return $null
    }
  }
  return $null
}

function ProxyHostPortFromListen([string]$Listen) {
  if ([string]::IsNullOrWhiteSpace($Listen)) { return "127.0.0.1:28657" }
  $l = $Listen.Trim()
  if ($l.StartsWith("0.0.0.0:")) { return "127.0.0.1:" + $l.Substring("0.0.0.0:".Length) }
  if ($l.StartsWith(":")) { return "127.0.0.1" + $l }
  return $l
}

function EnableAutostartTask([string]$VgPath, [string]$ConfigFile) {
  $taskName = "VibeGuard"
  $args = "--config `"$ConfigFile`" start --foreground"
  $action = New-ScheduledTaskAction -Execute "$VgPath" -Argument "$args"
  $trigger = New-ScheduledTaskTrigger -AtLogOn

  $userId = $null
  if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN) -and -not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
    $userId = "$($env:USERDOMAIN)\\$($env:USERNAME)"
  } elseif (-not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
    $userId = "$($env:USERNAME)"
  } else {
    $userId = "$([Environment]::UserName)"
  }

  $principal = New-ScheduledTaskPrincipal -UserId "$userId" -LogonType Interactive -RunLevel LeastPrivilege
  try {
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
  } catch {
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
  }

  Register-ScheduledTask -TaskName "$taskName" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "VibeGuard proxy autostart" -Force | Out-Null
  try { Start-ScheduledTask -TaskName "$taskName" | Out-Null } catch { }
  return $taskName
}

function EnableAutostartRunKey([string]$VgPath, [string]$ConfigFile) {
  $runKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  $vgEsc = $VgPath -replace "'", "''"
  $cfgEsc = $ConfigFile -replace "'", "''"
  $cmd = "& '$vgEsc' --config '$cfgEsc' start --foreground"
  $value = "powershell.exe -NoProfile -WindowStyle Hidden -Command `"$cmd`""
  New-Item -Path "$runKey" -Force | Out-Null
  New-ItemProperty -Path "$runKey" -Name "VibeGuard" -Value "$value" -PropertyType String -Force | Out-Null
  return $runKey
}

New-Item -ItemType Directory -Force -Path "$InstallDir" | Out-Null

Say "安装目录：$InstallDir" "Install dir: $InstallDir"
Say ("安装变体：$ScriptVariant") ("Variant: $ScriptVariant")

if (InRepo) {
  Need "go"
  Say "检测到仓库源码：从源码构建并安装" "Repo detected: build from source"
  $tmp = Join-Path $env:TEMP ("vibeguard-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path "$tmp" | Out-Null
  try {
    $outExe = Join-Path "$tmp" "vibeguard.exe"
    $args = @("build", "-o", "$outExe")
    if ($ScriptVariant -eq "full") { $args += @("-tags", "vibeguard_full") }
    $args += @("./cmd/vibeguard")
    Run "go" $args
    Copy-Item -Force -LiteralPath "$outExe" -Destination (Join-Path "$InstallDir" "vibeguard.exe")
  } finally {
    Remove-Item -Recurse -Force -LiteralPath "$tmp" -ErrorAction SilentlyContinue | Out-Null
  }
} else {
  $installed = $false
  try {
    InstallFromRelease "$InstallDir" "$ScriptVariant" "$Version"
    $installed = $true
  } catch {
    Write-Warning (T ("Release 安装失败，将改为从源码构建（" + $_.Exception.Message + "）") ("Release install failed; falling back to building from source (" + $_.Exception.Message + ")"))
  }

  if (-not $installed) {
    Need "go"
    Need "git"
    $repo = $env:VG_INSTALL_REPO
    if ([string]::IsNullOrWhiteSpace($repo)) { $repo = "Ignareo/VibeGuard" }
    $ref = $env:VG_INSTALL_REF
    if ([string]::IsNullOrWhiteSpace($ref)) { $ref = "main" }
    Say "未检测到源码：将从 $repo 克隆并构建" "Repo not found: cloning and building from $repo"
    $tmp = Join-Path $env:TEMP ("vibeguard-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path "$tmp" | Out-Null
    try {
      $src = Join-Path "$tmp" "src"
      Run "git" @("clone", "--depth", "1", "--branch", "$ref", "https://github.com/$repo.git", "$src")
      $outExe = Join-Path "$tmp" "vibeguard.exe"
      $args = @("build", "-o", "$outExe")
      if ($ScriptVariant -eq "full") { $args += @("-tags", "vibeguard_full") }
      $args += @("./cmd/vibeguard")
      Push-Location "$src"
      try {
        Run "go" $args
      } finally {
        Pop-Location
      }
      Copy-Item -Force -LiteralPath "$outExe" -Destination (Join-Path "$InstallDir" "vibeguard.exe")
    } finally {
      Remove-Item -Recurse -Force -LiteralPath "$tmp" -ErrorAction SilentlyContinue | Out-Null
    }
  }
}

$vg = Join-Path "$InstallDir" "vibeguard.exe"
if (-not (Test-Path -LiteralPath "$vg")) {
  $cmd = Get-Command "vibeguard" -ErrorAction SilentlyContinue
  if ($null -ne $cmd) {
    $vg = $cmd.Path
  }
}
if (-not (Test-Path -LiteralPath "$vg")) {
  Die "未找到 vibeguard：$vg" "vibeguard not found: $vg"
}

Say "vibeguard 路径：$vg" "vibeguard path: $vg"

$configDir = Join-Path $HOME ".vibeguard"
$caCert = Join-Path "$configDir" "ca.crt"
$configFile = Join-Path "$configDir" "config.yaml"

# Optional: make vibeguard globally callable (write to user PATH).
if ($PathMode -ne "skip") {
  $cmd = Get-Command "vibeguard" -ErrorAction SilentlyContinue
  $resolved = if ($null -ne $cmd) { $cmd.Path } else { $null }
  $needPath = $false
  if ($null -eq $resolved) { $needPath = $true }
  elseif (-not $resolved.Equals($vg, [System.StringComparison]::OrdinalIgnoreCase)) { $needPath = $true }

  if ($needPath) {
    $doIt = $false
    if ($PathMode -eq "user") {
      $doIt = $true
    } elseif (-not $NonInteractive) {
      $answer = Read-Host (T "检测到 vibeguard 可能无法全局调用，是否将安装目录写入用户 PATH？(Y/n)" "vibeguard may not be on PATH. Add install dir to user PATH? (Y/n)")
      if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "Y" }
      if ($answer -match '^(?i:y|yes)$') { $doIt = $true }
    } else {
      Write-Warning (T "非交互模式：未写入 PATH（可手动将 $InstallDir 加入用户 PATH）" "Non-interactive: PATH not modified (add $InstallDir to user PATH manually)")
    }

    if ($doIt) {
      $changed = EnsureUserPath "$InstallDir"
      if ($changed) {
        Say "已写入用户 PATH（需重开终端生效）" "Updated user PATH (restart terminal to apply)"
      } else {
        Say "用户 PATH 已包含该目录" "User PATH already contains this dir"
      }
      if (-not (PathContains $env:Path "$InstallDir")) {
        $env:Path = "$InstallDir;$($env:Path)"
      }
    }
  }
}

Say "检查 CA 证书" "Checking CA certificate"
if (-not (Test-Path -LiteralPath "$caCert")) {
  if (Test-Path -LiteralPath "$configFile") {
    Say "已存在配置但未找到 CA：请运行 vibeguard init 生成 CA" "Config exists but CA missing: run vibeguard init to generate CA"
  } else {
    Say "未找到 CA：将运行 vibeguard init 生成 CA" "CA not found: running vibeguard init to generate CA"
    if ($NonInteractive) {
      $tmp = Join-Path $env:TEMP ("vibeguard-init-" + [Guid]::NewGuid().ToString("N") + ".txt")
      try {
        $initInput = "`n`n`n`n3`n"
        [System.IO.File]::WriteAllText("$tmp", $initInput, [System.Text.UTF8Encoding]::new($false))
        $p = Start-Process -FilePath "$vg" -ArgumentList @("init") -RedirectStandardInput "$tmp" -NoNewWindow -Wait -PassThru
        if ($p.ExitCode -ne 0) {
          Write-Warning (T "init 返回非 0：$($p.ExitCode)" "init exited with non-zero: $($p.ExitCode)")
        }
      } finally {
        Remove-Item -Force -LiteralPath "$tmp" -ErrorAction SilentlyContinue | Out-Null
      }
    } else {
      & "$vg" "init"
    }
  }
}

if (Test-Path -LiteralPath "$caCert") {
  Say "CA 证书已就绪：$caCert" "CA certificate ready: $caCert"
} else {
  Say "仍未找到 CA 证书：跳过证书步骤" "CA certificate still missing: skipping cert steps"
  $Trust = "skip"
  $Export = $false
}

$exportWasProvided = $PSBoundParameters.ContainsKey('Export')
if (-not $NonInteractive -and (-not $exportWasProvided) -and (Test-Path -LiteralPath "$caCert")) {
  $ans = Read-Host (T "是否导出（下载）CA 证书到文件（便于排查/手动安装）？(y/N)" "Export CA certificate to a file (for debugging/manual install)? (y/N)")
  if ([string]::IsNullOrWhiteSpace($ans)) { $ans = "N" }
  if ($ans -match '^(?i:y|yes)$') { $Export = $true }
}

$trustWasProvided = $PSBoundParameters.ContainsKey('Trust')
if (-not $NonInteractive -and (-not $trustWasProvided) -and (Test-Path -LiteralPath "$caCert")) {
  $ans = Read-Host (T "是否安装信任证书（HTTPS MITM 必需，推荐）？(Y/n)" "Install trusted CA (required for HTTPS MITM, recommended)? (Y/n)")
  if ([string]::IsNullOrWhiteSpace($ans)) { $ans = "Y" }
  if ($ans -match '^(?i:n|no)$') { $Trust = "skip" } else { $Trust = "auto" }
}

if ($Export -and (Test-Path -LiteralPath "$caCert")) {
  $exportPath = $null
  $downloads = Join-Path $HOME "Downloads"
  if (Test-Path -LiteralPath "$downloads") {
    $exportPath = Join-Path "$downloads" "vibeguard-ca.crt"
  } else {
    $exportPath = (Join-Path (Get-Location) "vibeguard-ca.crt")
  }
  Copy-Item -Force -LiteralPath "$caCert" -Destination "$exportPath"
  Say "已导出（下载）CA 证书：$exportPath" "Exported CA certificate: $exportPath"
}

switch ($Trust) {
  "skip" {
    Say "跳过信任库安装" "Skipping trust store install"
  }
  "system" {
    Say "将安装到系统信任库（需要管理员权限）" "Installing to SYSTEM trust store (Administrator required)"
    if (-not (IsAdmin)) {
      Say "检测到当前不是管理员：将弹出 UAC 提示" "Not elevated: prompting UAC"
      $p = Start-Process -FilePath "$vg" -ArgumentList @("trust", "--mode", "system") -Verb RunAs -Wait -PassThru
      if ($p.ExitCode -ne 0) {
        Die "安装系统信任证书失败（exit=$($p.ExitCode)）" "Failed to install system trust certificate (exit=$($p.ExitCode))"
      }
    } else {
      Run "$vg" @("trust", "--mode", "system")
    }
  }
  "user" {
    Say "将安装到用户信任库" "Installing to USER trust store"
    Run "$vg" @("trust", "--mode", "user")
  }
  "auto" {
    Say "将自动选择信任库（先 user 再 system）" "Installing with AUTO mode (user then system)"
    Run "$vg" @("trust", "--mode", "auto")
  }
  default {
    Die "无效的 -Trust：$Trust" "Invalid -Trust: $Trust"
  }
}

$listen = GetListenFromConfig "$configFile"
$proxyHostPort = ProxyHostPortFromListen "$listen"
$proxyUrl = "http://$proxyHostPort"
$adminUrl = "http://$proxyHostPort/manager/"

# Optional: autostart (Windows Scheduled Task; fallback to HKCU Run).
$autostartEnabled = $false
$autostartHint = $null
if ($AutostartMode -ne "skip") {
  $doIt = $false
  if ($AutostartMode -eq "add") {
    $doIt = $true
  } elseif (-not $NonInteractive) {
    $answer = Read-Host (T "是否启用开机自启并后台运行（推荐）？(Y/n)" "Enable autostart + background run (recommended)? (Y/n)")
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "Y" }
    if ($answer -match '^(?i:y|yes)$') { $doIt = $true }
  } else {
    Write-Warning (T "非交互模式：未启用开机自启" "Non-interactive: autostart not configured")
  }

  if ($doIt) {
    $taskCmdOk = ($null -ne (Get-Command "Register-ScheduledTask" -ErrorAction SilentlyContinue)) -and
                 ($null -ne (Get-Command "New-ScheduledTaskAction" -ErrorAction SilentlyContinue)) -and
                 ($null -ne (Get-Command "New-ScheduledTaskTrigger" -ErrorAction SilentlyContinue)) -and
                 ($null -ne (Get-Command "New-ScheduledTaskPrincipal" -ErrorAction SilentlyContinue))

    if ($taskCmdOk) {
      try {
        $name = EnableAutostartTask "$vg" "$configFile"
        $autostartEnabled = $true
        $autostartHint = (T "计划任务：$name（可用“任务计划程序”禁用/删除）" "Task Scheduler: $name (disable/delete via Task Scheduler)")
        Say "已启用开机自启（计划任务）" "Autostart enabled (Task Scheduler)"
      } catch {
        Write-Warning (T ("计划任务创建失败，将退化为 HKCU Run：$($_.Exception.Message)") ("Failed to create scheduled task; falling back to HKCU Run: $($_.Exception.Message)"))
      }
    }

    if (-not $autostartEnabled) {
      try {
        $where = EnableAutostartRunKey "$vg" "$configFile"
        $autostartEnabled = $true
        $autostartHint = (T "HKCU Run：登录后自动启动（可在注册表或启动项中移除）" "HKCU Run: starts on logon (remove via registry/startup apps)")
        Say "已启用开机自启（HKCU Run）" "Autostart enabled (HKCU Run)"
      } catch {
        Write-Warning (T ("启用开机自启失败：$($_.Exception.Message)") ("Failed to enable autostart: $($_.Exception.Message)"))
      }
    }
  }
}

Say "启动后台代理" "Starting proxy in background"
try {
  & "$vg" "start" | Out-Null
} catch { }

# Optional: launcher functions for CLI assistants. PowerShell aliases cannot take
# arguments, so the user adds small functions to $PROFILE; we only print them.
if (-not $NonInteractive) {
  $ans = Read-Host (T "是否为常用 CLI 助手添加启动函数（kimi/opencode，需手动加入 `$PROFILE）？(y/N)" "Add launcher functions for CLI assistants (kimi/opencode, requires a manual `$PROFILE edit)? (y/N)")
  if ([string]::IsNullOrWhiteSpace($ans)) { $ans = "N" }
  if ($ans -match '^(?i:y|yes)$') {
    Say "请将以下函数加入 `$PROFILE（可运行“echo `$PROFILE”查看路径，用记事本打开编辑）：" "Add the following functions to your `$PROFILE (run 'echo `$PROFILE' for the path and edit it with notepad):"
    Write-Host ""
    Write-Host "    function kimi { vibeguard kimi @args }"
    Write-Host "    function opencode { vibeguard opencode @args }"
    Write-Host ""
    Write-Host (T "    若已存在同名的 function/alias，请先移除，避免重复定义。" "    Remove any existing function/alias with the same name first to avoid duplicates.")
  } else {
    Say "已跳过启动函数提示" "Skipped launcher function hint"
  }
}

Say "安装完成" "Done"
Write-Host ""
Write-Host (T "下一步：" "Next steps:")
if ($autostartEnabled) {
  Write-Host (T "  1) 代理已设置为开机自启（登录后自动运行）" "  1) Proxy runs automatically on logon")
  if ($null -ne $autostartHint) { Write-Host ("     " + $autostartHint) }
} else {
  Write-Host (T "  1) 启动代理（后台）：$vg start" "  1) Start proxy (background): $vg start")
  Write-Host (T "     前台调试：$vg start --foreground" "     Foreground debug: $vg start --foreground")
}

Write-Host (T "  2) 打开管理页：$adminUrl" "  2) Open admin: $adminUrl")
Write-Host (T "  3) CLI 编程助手推荐用 VibeGuard 启动（仅该进程生效）：" "  3) For CLI assistants, launch via VibeGuard (process-only):")
Write-Host "     vibeguard codex [args...]"
Write-Host "     vibeguard claude [args...]"
Write-Host "     vibeguard gemini [args...]"
Write-Host "     vibeguard opencode [args...]"
Write-Host "     vibeguard qwen [args...]"
Write-Host "     vibeguard kimi [args...]"
Write-Host "     vibeguard run <command> [args...]"
Write-Host (T "  4) IDE/GUI（如 Cursor）在软件设置里把代理地址填为：$proxyUrl" "  4) For IDE/GUI apps (Cursor, etc), set the proxy URL to: $proxyUrl")
