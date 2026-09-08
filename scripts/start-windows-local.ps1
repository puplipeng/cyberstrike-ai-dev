$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-LaunchError([string]$Message) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [void][System.Windows.Forms.MessageBox]::Show(
            $Message,
            'CyberStrikeAI startup failed',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    } catch { }
}

if (-not (Test-IsAdministrator)) {
    try {
        $hostExe = (Get-Process -Id $PID -ErrorAction Stop).Path
        $escapedScript = $PSCommandPath.Replace('"', '""')
        $argumentLine = '-NoProfile -ExecutionPolicy Bypass -File "' + $escapedScript + '"'
        Start-Process -FilePath $hostExe -ArgumentList $argumentLine -Verb RunAs -WindowStyle Hidden | Out-Null
    } catch {
        Show-LaunchError ('Administrator approval is required to start the local SSH vault and services.' + [Environment]::NewLine + $_.Exception.Message)
        exit 1
    }
    exit
}

$launchMutex = New-Object Threading.Mutex($false, 'Local\CyberStrikeAI-Desktop-Launcher')
$ownsLaunchMutex = $false
try {
    $ownsLaunchMutex = $launchMutex.WaitOne(120000)
} catch [Threading.AbandonedMutexException] {
    $ownsLaunchMutex = $true
}
if (-not $ownsLaunchMutex) {
    $launchMutex.Dispose()
    exit
}
$launchExitCode = 0

$repoRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$workRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $repoRoot)).Path
$serverExe = [IO.Path]::GetFullPath((Join-Path $repoRoot 'cyberstrike-ai.exe'))
$configPath = [IO.Path]::GetFullPath((Join-Path $repoRoot 'config.local.yaml'))
$pgCtl = [IO.Path]::GetFullPath((Join-Path $workRoot 'runtime\pgsql\bin\pg_ctl.exe'))
$pgData = [IO.Path]::GetFullPath((Join-Path $workRoot 'pgdata'))
$ollamaExe = [IO.Path]::GetFullPath((Join-Path $workRoot 'runtime\ollama-v0.33.1\ollama.exe'))
$modelRoot = [IO.Path]::GetFullPath((Join-Path $workRoot 'models'))
$ollamaProfile = [IO.Path]::GetFullPath((Join-Path $workRoot 'ollama-profile'))
$ollamaTemp = [IO.Path]::GetFullPath((Join-Path $workRoot 'ollama-tmp'))
$codexWorkdir = [IO.Path]::GetFullPath((Join-Path $workRoot 'codex-bridge'))
$logRoot = [IO.Path]::GetFullPath((Join-Path $workRoot 'logs'))
$serverPIDFile = [IO.Path]::GetFullPath((Join-Path $workRoot 'server.pid'))
$embeddingPIDFile = [IO.Path]::GetFullPath((Join-Path $workRoot 'embedding.pid'))
$launcherLog = [IO.Path]::GetFullPath((Join-Path $logRoot 'desktop-launcher.log'))
$appURL = 'http://127.0.0.1:8080/'

function Assert-ChildPath([string]$Path, [string]$Parent, [string]$Label) {
    if (-not $Path.StartsWith($Parent + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escaped its expected root: $Path"
    }
}

function Test-HTTPReady([string]$URI) {
    try {
        $response = Invoke-WebRequest -Uri $URI -UseBasicParsing -TimeoutSec 3
        return [int]$response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Get-ListenerOwners([int]$Port) {
    $owners = @()
    $connections = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    foreach ($ownerPID in @($connections | Select-Object -ExpandProperty OwningProcess -Unique)) {
        $process = Get-Process -Id $ownerPID -ErrorAction SilentlyContinue
        if ($process) { $owners += $process }
    }
    return $owners
}

function Assert-ExpectedListener([int]$Port, [string]$ExpectedPath) {
    $owners = @(Get-ListenerOwners $Port)
    foreach ($owner in $owners) {
        if ($owner.Path -ine $ExpectedPath) {
            throw "Port $Port is already owned by unexpected process $($owner.Id): $($owner.Path)"
        }
    }
    return $owners
}

function Set-ProcessEnvironment([hashtable]$Values) {
    $previous = @{}
    foreach ($name in $Values.Keys) {
        $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, [string]$Values[$name], 'Process')
    }
    return $previous
}

function Restore-ProcessEnvironment([hashtable]$Values) {
    foreach ($name in $Values.Keys) {
        [Environment]::SetEnvironmentVariable($name, $Values[$name], 'Process')
    }
}

function Write-PIDFileAtomically([string]$Path, [int]$ProcessID) {
    $directory = Split-Path -Parent $Path
    $temporary = Join-Path $directory ('.' + [IO.Path]::GetFileName($Path) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $temporary + '.bak'
    try {
        [IO.File]::WriteAllText($temporary, [string]$ProcessID, [Text.Encoding]::ASCII)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporary, $Path, $backup, $true)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        foreach ($transient in @($temporary, $backup)) {
            if (Test-Path -LiteralPath $transient -PathType Leaf) {
                Remove-Item -LiteralPath $transient -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Stop-StartedProcess([Diagnostics.Process]$Process, [string]$ExpectedPath, [string]$PIDFile) {
    if (-not $Process) { return }
    $processID = $Process.Id
    try {
        $Process.Refresh()
        if (-not $Process.HasExited -and $Process.Path -ieq $ExpectedPath) {
            Stop-Process -Id $processID -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $processID -Timeout 10 -ErrorAction SilentlyContinue
        }
    } finally {
        if (Test-Path -LiteralPath $PIDFile -PathType Leaf) {
            $savedPID = 0
            if ([int]::TryParse(([IO.File]::ReadAllText($PIDFile).Trim()), [ref]$savedPID) -and $savedPID -eq $processID) {
                Remove-Item -LiteralPath $PIDFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Find-CodexExecutable {
    $command = Get-Command codex.exe -ErrorAction SilentlyContinue
    if ($command -and (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
        return $command.Source
    }
    $binRoot = Join-Path $env:LOCALAPPDATA 'OpenAI\Codex\bin'
    if (Test-Path -LiteralPath $binRoot -PathType Container) {
        $candidate = Get-ChildItem -LiteralPath $binRoot -Recurse -File -Filter 'codex.exe' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return $null
}

try {
    Assert-ChildPath $serverExe $repoRoot 'Server executable'
    Assert-ChildPath $configPath $repoRoot 'Runtime configuration'
    Assert-ChildPath $pgCtl $workRoot 'PostgreSQL controller'
    Assert-ChildPath $pgData $workRoot 'PostgreSQL data'
    Assert-ChildPath $ollamaExe $workRoot 'Embedding executable'
    Assert-ChildPath $logRoot $workRoot 'Log directory'

    foreach ($requiredFile in @($serverExe, $configPath, $pgCtl, $ollamaExe)) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Required file is missing: $requiredFile"
        }
    }
    foreach ($directory in @($logRoot, $modelRoot, $ollamaProfile, $ollamaTemp, $codexWorkdir)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    Add-Content -LiteralPath $launcherLog -Encoding UTF8 -Value ("[{0}] Startup requested." -f (Get-Date).ToString('o'))

    & $pgCtl -D $pgData status *> $null
    if ($LASTEXITCODE -ne 0) {
        & $pgCtl -D $pgData -l (Join-Path $logRoot 'postgresql.log') -w start
        if ($LASTEXITCODE -ne 0) {
            throw 'PostgreSQL did not start. Inspect work\logs\postgresql.log.'
        }
    }

    $embeddingReady = Test-HTTPReady 'http://127.0.0.1:11435/api/version'
    $embeddingOwners = @(Assert-ExpectedListener 11435 $ollamaExe)
    if ($embeddingReady -and $embeddingOwners.Count -eq 0) {
        throw 'Embedding endpoint responded, but its owning process could not be verified.'
    }
    if (-not $embeddingReady) {
        if ($embeddingOwners.Count -gt 0) {
            throw 'The embedding process owns port 11435 but is not healthy.'
        }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $embeddingOut = Join-Path $logRoot ("embedding-start-$stamp.out.log")
        $embeddingErr = Join-Path $logRoot ("embedding-start-$stamp.err.log")
        $embeddingEnvironment = @{
            OLLAMA_HOST = '127.0.0.1:11435'
            OLLAMA_MODELS = $modelRoot
            OLLAMA_NO_CLOUD = '1'
            OLLAMA_MAX_LOADED_MODELS = '1'
            OLLAMA_NUM_PARALLEL = '1'
            OLLAMA_ORIGINS = 'http://127.0.0.1:11435'
            USERPROFILE = $ollamaProfile
            TEMP = $ollamaTemp
            TMP = $ollamaTemp
        }
        $previousEnvironment = Set-ProcessEnvironment $embeddingEnvironment
        try {
            $embeddingProcess = Start-Process -FilePath $ollamaExe -ArgumentList 'serve' -WorkingDirectory $workRoot -WindowStyle Hidden -RedirectStandardOutput $embeddingOut -RedirectStandardError $embeddingErr -PassThru
        } finally {
            Restore-ProcessEnvironment $previousEnvironment
        }
        Write-PIDFileAtomically $embeddingPIDFile $embeddingProcess.Id
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            $embeddingProcess.Refresh()
            if ($embeddingProcess.HasExited) {
                Stop-StartedProcess $embeddingProcess $ollamaExe $embeddingPIDFile
                throw "Embedding service exited with code $($embeddingProcess.ExitCode). Inspect $embeddingErr."
            }
            if (Test-HTTPReady 'http://127.0.0.1:11435/api/version') {
                $embeddingReady = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $embeddingReady) {
            Stop-StartedProcess $embeddingProcess $ollamaExe $embeddingPIDFile
            throw "Embedding service did not become ready. Inspect $embeddingErr."
        }
        try {
            $verifiedEmbeddingOwners = @(Assert-ExpectedListener 11435 $ollamaExe)
        } catch {
            Stop-StartedProcess $embeddingProcess $ollamaExe $embeddingPIDFile
            throw
        }
        if ($verifiedEmbeddingOwners.Count -ne 1 -or $verifiedEmbeddingOwners[0].Id -ne $embeddingProcess.Id) {
            Stop-StartedProcess $embeddingProcess $ollamaExe $embeddingPIDFile
            throw 'Embedding endpoint ownership changed during startup.'
        }
    } elseif ($embeddingOwners.Count -eq 1) {
        Write-PIDFileAtomically $embeddingPIDFile $embeddingOwners[0].Id
    } else {
        throw 'More than one embedding listener was detected.'
    }

    $serverReady = Test-HTTPReady $appURL
    $serverOwners = @(Assert-ExpectedListener 8080 $serverExe)
    if ($serverReady -and $serverOwners.Count -eq 0) {
        throw 'CyberStrikeAI responded, but its owning process could not be verified.'
    }
    if (-not $serverReady) {
        if ($serverOwners.Count -gt 0) {
            throw 'CyberStrikeAI owns port 8080 but is not healthy.'
        }
        $orphanServers = @(Get-Process -Name 'cyberstrike-ai' -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $serverExe })
        if ($orphanServers.Count -gt 0) {
            throw "CyberStrikeAI process $($orphanServers[0].Id) exists without a healthy listener. Stop it before retrying."
        }

        $serverEnvironment = @{ CYBERSTRIKE_CODEX_WORKDIR = $codexWorkdir }
        $codexExe = Find-CodexExecutable
        if ($codexExe) { $serverEnvironment['CYBERSTRIKE_CODEX_BIN'] = $codexExe }
        $previousEnvironment = Set-ProcessEnvironment $serverEnvironment
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $serverOut = Join-Path $logRoot ("cyberstrike-start-$stamp.out.log")
        $serverErr = Join-Path $logRoot ("cyberstrike-start-$stamp.err.log")
        try {
            $serverProcess = Start-Process -FilePath $serverExe -ArgumentList @('-config', 'config.local.yaml', '--http') -WorkingDirectory $repoRoot -WindowStyle Hidden -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -PassThru
        } finally {
            Restore-ProcessEnvironment $previousEnvironment
        }
        Write-PIDFileAtomically $serverPIDFile $serverProcess.Id
        for ($attempt = 0; $attempt -lt 60; $attempt++) {
            $serverProcess.Refresh()
            if ($serverProcess.HasExited) {
                Stop-StartedProcess $serverProcess $serverExe $serverPIDFile
                throw "CyberStrikeAI exited with code $($serverProcess.ExitCode). Inspect $serverOut and $serverErr."
            }
            if (Test-HTTPReady $appURL) {
                $serverReady = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $serverReady) {
            Stop-StartedProcess $serverProcess $serverExe $serverPIDFile
            throw "CyberStrikeAI did not become ready. Inspect $serverOut and $serverErr."
        }
        try {
            $verifiedServerOwners = @(Assert-ExpectedListener 8080 $serverExe)
        } catch {
            Stop-StartedProcess $serverProcess $serverExe $serverPIDFile
            throw
        }
        if ($verifiedServerOwners.Count -ne 1 -or $verifiedServerOwners[0].Id -ne $serverProcess.Id) {
            Stop-StartedProcess $serverProcess $serverExe $serverPIDFile
            throw 'CyberStrikeAI endpoint ownership changed during startup.'
        }
    } elseif ($serverOwners.Count -eq 1) {
        Write-PIDFileAtomically $serverPIDFile $serverOwners[0].Id
    } else {
        throw 'More than one CyberStrikeAI listener was detected.'
    }

    Add-Content -LiteralPath $launcherLog -Encoding UTF8 -Value ("[{0}] Startup completed: {1}" -f (Get-Date).ToString('o'), $appURL)
    Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList $appURL | Out-Null
} catch {
    $message = $_.Exception.Message
    try {
        New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
        Add-Content -LiteralPath $launcherLog -Encoding UTF8 -Value ("[{0}] ERROR: {1}" -f (Get-Date).ToString('o'), $message)
    } catch { }
    Show-LaunchError ($message + [Environment]::NewLine + [Environment]::NewLine + "Log: $launcherLog")
    $launchExitCode = 1
} finally {
    if ($ownsLaunchMutex) {
        try { $launchMutex.ReleaseMutex() } catch { }
    }
    $launchMutex.Dispose()
}
if ($launchExitCode -ne 0) { exit $launchExitCode }
