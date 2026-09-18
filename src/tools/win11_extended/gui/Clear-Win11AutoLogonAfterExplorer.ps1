[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InteractiveUser,
    [Parameter(Mandatory = $true)][string]$ResultPath,
    [ValidateRange(30,900)][int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$found = $false
$sessionId = 0
$explorerPid = 0
$failureMessage = $null
try {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        foreach ($candidate in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)) {
            try {
                $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwner -ErrorAction Stop
                if ([uint32]$owner.ReturnValue -eq 0 -and [uint32]$candidate.SessionId -gt 0 -and
                    [string]$owner.User -ieq $InteractiveUser) {
                    $found = $true
                    $sessionId = [uint32]$candidate.SessionId
                    $explorerPid = [uint32]$candidate.ProcessId
                    break
                }
            } catch {}
        }
        if ($found) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $found) { throw 'Interactive Explorer was not observed before AutoAdminLogon cleanup timeout.' }
} catch {
    $failureMessage = $_.Exception.Message
} finally {
    Remove-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue
    Remove-ItemProperty -LiteralPath $key -Name AutoLogonCount -ErrorAction SilentlyContinue
    New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '0' -PropertyType String -Force | Out-Null
    $secretPresent = $null -ne (Get-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue)
    $result = [ordered]@{
        schema='kdbg.win11-extended-gui-autologon-cleanup.v1'
        success=$found -and -not $secretPresent
        completed_utc=[DateTime]::UtcNow.ToString('o')
        explorer_observed=$found
        session_id=$sessionId
        explorer_pid=$explorerPid
        default_password_present=$secretPresent
        error=$failureMessage
        plaintext_password_logged=$false
    }
    [IO.File]::WriteAllText($ResultPath,($result | ConvertTo-Json -Depth 10) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}
if (-not $result.success) { throw 'AutoAdminLogon cleanup did not complete successfully.' }
