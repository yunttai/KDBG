[CmdletBinding()]
param(
    [Parameter()][string]$OutputPath = (Join-Path $PSScriptRoot 'static-validation.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Win11ValidationHarness.psm1') -Force

$result = Test-KdbgWin11ValidationWorkspace -WorkspaceRoot $PSScriptRoot
$json = $result | ConvertTo-Json -Depth 20
$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
$root = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
if (-not $resolvedOutput.StartsWith(($root + '\'), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Static validation output must remain below the workspace.'
}
$cursor = if (Test-Path -LiteralPath $resolvedOutput) { $resolvedOutput } else { Split-Path -Parent $resolvedOutput }
while ($cursor.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
    if (Test-Path -LiteralPath $cursor) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Static validation output may not traverse a reparse point.'
        }
    }
    if ($cursor -eq $root) { break }
    $cursor = Split-Path -Parent $cursor
}
[IO.File]::WriteAllText($resolvedOutput, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
$result
if (-not $result.success) { exit 2 }
