<#
.SYNOPSIS
  VCF AIops 배포 조각(*.partNN)을 순서대로 합치고 SHA256SUMS 로 검증한다.

.DESCRIPTION
  · 같은 폴더의  <이름>.part00, .part01 … 을 번호 순으로 이어 붙여 <이름> 을 만든다(바이너리, 스트림 복사).
  · 조각 번호가 빠지면(part03 다음 part05 등) 중단한다.
  · 합친 뒤 SHA256SUMS(또는 -Sums 로 지정한 파일)의 해시와 비교한다. 조각이 없는 항목(소스 tar 등)도 파일이 있으면 함께 검증한다.
  · 이미 합쳐진 파일이 있고 해시가 맞으면 건너뛰고, 틀리면 -Force 없이는 덮어쓰지 않는다.
  · 종료 코드: 0 = 모두 OK, 1 = 해시 불일치·누락·오류.

.EXAMPLE
  PS> .\Join-Parts.ps1
  PS> .\Join-Parts.ps1 -Path D:\downloads\vcf-aiops-2.1.0 -DeleteParts
  PS> powershell -ExecutionPolicy Bypass -File .\Join-Parts.ps1 -Force

.NOTES
  Windows PowerShell 5.1 / PowerShell 7 공통. 외부 도구 불필요(.NET FileStream + Get-FileHash).
#>
[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot,          # 조각·SHA256SUMS 가 있는 폴더(기본: 스크립트 위치)
    [string]$Sums = "SHA256SUMS",           # 체크섬 파일 이름(또는 전체 경로)
    [switch]$Force,                         # 해시가 다른 기존 파일을 다시 만든다
    [switch]$DeleteParts,                   # 검증 통과한 파일의 조각을 삭제한다
    [switch]$NoVerify                       # 합치기만 하고 검증은 생략(권장하지 않음)
)

$ErrorActionPreference = "Stop"
if (-not $Path) { $Path = (Get-Location).Path }
$Path = (Resolve-Path $Path).Path
$sumsPath = if ([System.IO.Path]::IsPathRooted($Sums)) { $Sums } else { Join-Path $Path $Sums }

function Write-Step([string]$msg, [string]$color = "Cyan") { Write-Host ("▶ " + $msg) -ForegroundColor $color }
function Write-Ok([string]$msg)   { Write-Host ("  ✔ " + $msg) -ForegroundColor Green }
function Write-Bad([string]$msg)  { Write-Host ("  ✘ " + $msg) -ForegroundColor Red }
function Fmt-Size([long]$b) { if ($b -ge 1GB) { "{0:N2} GB" -f ($b / 1GB) } elseif ($b -ge 1MB) { "{0:N1} MB" -f ($b / 1MB) } else { "{0:N0} KB" -f ($b / 1KB) } }

# ---------------------------------------------------------------- 1. 체크섬 파일 읽기 (형식: "<sha256>  <파일명>")
$expected = @{}
if (Test-Path $sumsPath) {
    foreach ($line in Get-Content $sumsPath) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') { $expected[$Matches[2]] = $Matches[1].ToLower() }
    }
    Write-Step ("체크섬 파일: {0} ({1}개 항목)" -f $sumsPath, $expected.Count)
} elseif (-not $NoVerify) {
    Write-Bad "체크섬 파일을 찾을 수 없습니다: $sumsPath  (-Sums 로 지정하거나 -NoVerify)"
    exit 1
}

# ---------------------------------------------------------------- 2. 조각 묶기 (이름.partNN → 이름)
$groups = Get-ChildItem -LiteralPath $Path -File |
    Where-Object { $_.Name -match '^(.+)\.part(\d+)$' } |
    ForEach-Object { [pscustomobject]@{ Target = $Matches[1]; Index = [int]$Matches[2]; File = $_ } } |
    Group-Object Target

$failed = 0
$merged = @()

foreach ($g in $groups) {
    $target = Join-Path $Path $g.Name
    $parts  = $g.Group | Sort-Object Index
    $total  = ($parts | Measure-Object -Property { $_.File.Length } -Sum).Sum
    Write-Step ("{0}  ← 조각 {1}개, {2}" -f $g.Name, $parts.Count, (Fmt-Size $total))

    # 번호 연속성
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i].Index -ne $i) {
            Write-Bad ("조각 번호가 비었습니다: part{0:D2} 가 없음 (있는 번호: {1})" -f $i, (($parts | ForEach-Object { $_.Index }) -join ","))
            $failed++; continue
        }
    }
    if (($parts | ForEach-Object { $_.Index }) -join "," -ne ((0..($parts.Count - 1)) -join ",")) { continue }

    # 이미 있는 결과 파일
    if (Test-Path -LiteralPath $target) {
        $cur = Get-Item -LiteralPath $target
        if ($expected.ContainsKey($g.Name)) {
            $h = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
            if ($h -eq $expected[$g.Name]) { Write-Ok ("이미 합쳐져 있고 해시 일치 — 건너뜀 ({0})" -f (Fmt-Size $cur.Length)); $merged += $g.Name; continue }
            if (-not $Force) { Write-Bad "기존 파일의 해시가 다릅니다. 다시 만들려면 -Force"; $failed++; continue }
            Write-Host "  기존 파일 해시 불일치 → 다시 만듭니다(-Force)" -ForegroundColor Yellow
        } elseif ($cur.Length -eq $total -and -not $Force) {
            Write-Ok "이미 합쳐져 있음(크기 일치) — 건너뜀"; $merged += $g.Name; continue
        }
    }

    # 스트림 이어 붙이기 (임시 파일 → 완료 후 이름 변경: 중간에 끊겨도 반쪽 파일이 남지 않음)
    $tmp = "$target.joining"
    $out = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $buf = New-Object byte[] (4MB)
        $done = 0L
        foreach ($p in $parts) {
            $in = [System.IO.File]::Open($p.File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) { $out.Write($buf, 0, $n); $done += $n }
            } finally { $in.Dispose() }
            Write-Progress -Activity ("합치는 중: " + $g.Name) -Status $p.File.Name -PercentComplete ([int](100 * $done / [Math]::Max(1, $total)))
        }
    } finally { $out.Dispose(); Write-Progress -Activity ("합치는 중: " + $g.Name) -Completed }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    Rename-Item -LiteralPath $tmp -NewName (Split-Path $target -Leaf)
    $size = (Get-Item -LiteralPath $target).Length
    if ($size -ne $total) { Write-Bad ("크기 불일치: 조각 합 {0} ≠ 결과 {1}" -f $total, $size); $failed++; continue }
    Write-Ok ("합침 완료 {0}" -f (Fmt-Size $size))
    $merged += $g.Name
}

if ($groups.Count -eq 0) { Write-Host "조각(*.partNN) 파일이 없습니다 — 검증만 수행합니다." -ForegroundColor Yellow }

# ---------------------------------------------------------------- 3. SHA-256 검증 (합친 파일 + 체크섬 목록의 나머지 파일)
$verified = @()
if (-not $NoVerify) {
    Write-Step "SHA-256 검증"
    foreach ($name in ($expected.Keys | Sort-Object)) {
        $f = Join-Path $Path $name
        if (-not (Test-Path -LiteralPath $f)) { Write-Host ("  - {0}: 파일 없음(건너뜀)" -f $name) -ForegroundColor DarkGray; continue }
        $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower()
        if ($h -eq $expected[$name]) { Write-Ok ("{0}  {1}" -f $name, $h); $verified += $name }
        else { Write-Bad ("{0}`n      기대 {1}`n      실제 {2}" -f $name, $expected[$name], $h); $failed++ }
    }
    foreach ($name in $merged) {
        if (-not $expected.ContainsKey($name)) { Write-Host ("  ! {0}: 체크섬 목록에 없어 검증 불가" -f $name) -ForegroundColor Yellow }
    }
}

# ---------------------------------------------------------------- 4. 조각 삭제(검증 통과분만)
if ($DeleteParts) {
    foreach ($g in $groups) {
        if ($NoVerify -or $verified -contains $g.Name) {
            $g.Group | ForEach-Object { Remove-Item -LiteralPath $_.File.FullName -Force }
            Write-Ok ("{0} 조각 {1}개 삭제" -f $g.Name, $g.Group.Count)
        }
    }
}

Write-Host ""
if ($failed -eq 0) { Write-Host "모두 정상입니다." -ForegroundColor Green; exit 0 }
else { Write-Host ("문제 {0}건 — 해당 조각을 다시 내려받으세요." -f $failed) -ForegroundColor Red; exit 1 }
