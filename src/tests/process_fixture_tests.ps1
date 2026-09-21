[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FixturePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$FixtureFull = [IO.Path]::GetFullPath($FixturePath)
if (-not (Test-Path -LiteralPath $FixtureFull -PathType Leaf)) {
    throw "Fixture executable is missing: $FixtureFull"
}

$TempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$WorkDirectory = [IO.Path]::GetFullPath((Join-Path $TempRoot (
    'kdbg-process-fixture-test-' + [Guid]::NewGuid().ToString('N'))))
$TempPrefix = $TempRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if (-not $WorkDirectory.StartsWith(
        $TempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Resolved fixture test directory escaped the system temporary directory.'
}
New-Item -ItemType Directory -Path $WorkDirectory | Out-Null

$Stdout = Join-Path $WorkDirectory 'stdout.jsonl'
$Stderr = Join-Path $WorkDirectory 'stderr.log'
$Process = $null
$PipeName = $null
$Checks = 0

function Assert-True([bool]$Condition, [string]$Message) {
    $script:Checks++
    if (-not $Condition) { throw $Message }
}

function Invoke-FixtureCommand([string]$Command) {
    if ([string]::IsNullOrWhiteSpace($script:PipeName)) {
        throw 'Fixture pipe name is unavailable.'
    }
    $Client = [IO.Pipes.NamedPipeClientStream]::new(
        '.', $script:PipeName, [IO.Pipes.PipeDirection]::InOut)
    try {
        $Client.Connect(3000)
        $Client.ReadMode = [IO.Pipes.PipeTransmissionMode]::Message
        $Utf8 = [Text.UTF8Encoding]::new($false)
        $Writer = [IO.StreamWriter]::new($Client, $Utf8, 4096, $true)
        $Reader = [IO.StreamReader]::new($Client, $Utf8, $false, 4096, $true)
        try {
            $Writer.WriteLine($Command)
            $Writer.Flush()
            $Line = $Reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($Line)) {
                throw "Fixture returned no response for command: $Command"
            }
            return $Line | ConvertFrom-Json
        }
        finally {
            $Reader.Dispose()
            $Writer.Dispose()
        }
    }
    finally {
        $Client.Dispose()
    }
}

try {
    $Process = Start-Process -FilePath $FixtureFull `
        -RedirectStandardOutput $Stdout `
        -RedirectStandardError $Stderr `
        -WindowStyle Hidden `
        -PassThru

    $Deadline = [DateTime]::UtcNow.AddSeconds(10)
    $StartupLine = $null
    do {
        Start-Sleep -Milliseconds 50
        if (Test-Path -LiteralPath $Stdout -PathType Leaf) {
            $StartupLine = Get-Content -LiteralPath $Stdout -First 1
        }
    } while ([string]::IsNullOrWhiteSpace($StartupLine) -and
        [DateTime]::UtcNow -lt $Deadline -and -not $Process.HasExited)

    Assert-True (-not [string]::IsNullOrWhiteSpace($StartupLine)) `
        'Fixture did not publish startup metadata.'
    $Startup = $StartupLine | ConvertFrom-Json
    Assert-True ($Startup.schema -ceq 'kdbg.process-fixture.v1') `
        'Fixture startup schema mismatch.'
    Assert-True ($Startup.ok -eq $true) 'Fixture startup did not report success.'
    Assert-True ([UInt32]$Startup.protocol_version -eq 1) `
        'Fixture protocol version mismatch.'
    Assert-True ([UInt32]$Startup.pid -eq [UInt32]$Process.Id) `
        'Fixture PID does not match the launched process.'
    Assert-True ([UInt32]$Startup.byte_count -eq 4096) `
        'Fixture byte count is not 4096.'
    $VirtualAddress = [Convert]::ToUInt64(
        ([string]$Startup.virtual_address).Substring(2), 16)
    Assert-True ($VirtualAddress -ne 0 -and ($VirtualAddress -band 0xFFF) -eq 0) `
        'Fixture VA is not non-zero and page aligned.'
    Assert-True ([string]$Startup.fixture_nonce -cmatch '^[0-9a-f]{32}$') `
        'Fixture nonce is not exactly 16 lowercase hex bytes.'
    Assert-True ($Startup.virtual_locked -eq $true) `
        'Fixture did not confirm VirtualLock.'
    Assert-True (
        [string]$Startup.baseline_crc32 -ceq [string]$Startup.current_crc32) `
        'Fixture startup CRCs do not match.'

    $PipePath = [string]$Startup.pipe_name
    $PipePrefix = '\\.\pipe\'
    Assert-True ($PipePath.StartsWith(
        $PipePrefix, [StringComparison]::OrdinalIgnoreCase)) `
        'Fixture returned an invalid local pipe path.'
    $PipeName = $PipePath.Substring($PipePrefix.Length)

    $Info = Invoke-FixtureCommand 'INFO'
    Assert-True ($Info.ok -eq $true -and [UInt32]$Info.pid -eq [UInt32]$Process.Id) `
        'INFO did not preserve fixture identity.'

    $OutOfBounds = Invoke-FixtureCommand 'MUTATE 4095 0011'
    Assert-True ($OutOfBounds.ok -eq $false -and
        $OutOfBounds.error -ceq 'invalid_or_out_of_bounds_mutation') `
        'Out-of-bounds mutation was not rejected.'

    $Mutation = Invoke-FixtureCommand 'MUTATE 0x180 a5'
    Assert-True ($Mutation.ok -eq $true -and
        [string]$Mutation.current_crc32 -cne [string]$Mutation.baseline_crc32) `
        'Bounded mutation did not change the current CRC.'

    $BadVerify = Invoke-FixtureCommand (
        'VERIFY {0} {1}' -f $Startup.generation, $Startup.baseline_crc32)
    Assert-True ($BadVerify.ok -eq $false -and
        $BadVerify.error -ceq 'verification_mismatch') `
        'VERIFY did not reject mutated content.'

    $Reset = Invoke-FixtureCommand 'RESET'
    Assert-True ($Reset.ok -eq $true -and
        [UInt32]$Reset.generation -eq ([UInt32]$Startup.generation + 1)) `
        'RESET did not advance the fixture generation.'
    Assert-True ([string]$Reset.current_crc32 -ceq [string]$Reset.baseline_crc32) `
        'RESET did not restore the baseline CRC.'

    $GoodVerify = Invoke-FixtureCommand (
        'VERIFY {0} {1}' -f $Reset.generation, $Reset.current_crc32)
    Assert-True ($GoodVerify.ok -eq $true) `
        'VERIFY rejected the reset fixture generation and CRC.'

    $Exit = Invoke-FixtureCommand 'EXIT'
    Assert-True ($Exit.ok -eq $true -and $Exit.command -ceq 'EXIT') `
        'EXIT did not return a successful response.'
    Assert-True ($Process.WaitForExit(5000)) 'Fixture did not exit on command.'
    Assert-True ($Process.ExitCode -eq 0) 'Fixture exited with a failure code.'
    $ErrorText = if (Test-Path -LiteralPath $Stderr) {
        Get-Content -LiteralPath $Stderr -Raw
    } else { '' }
    Assert-True ([string]::IsNullOrWhiteSpace($ErrorText)) `
        'Fixture wrote an unexpected error message.'

    Write-Host "Process fixture protocol tests PASS: $Checks checks"
}
finally {
    if ($null -ne $Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
    if (Test-Path -LiteralPath $WorkDirectory) {
        $ResolvedWork = [IO.Path]::GetFullPath($WorkDirectory)
        if ($ResolvedWork.StartsWith(
                $TempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $ResolvedWork -Recurse -Force
        }
    }
}
