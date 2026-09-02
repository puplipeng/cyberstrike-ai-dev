[CmdletBinding()]
param(
    [string]$RuntimeRoot = 'D:\Projects\CyberStrikeAI\work\runtime\security-tools'
)

$ErrorActionPreference = 'Stop'
$headers = @{ 'User-Agent' = 'CyberStrikeAI-tool-installer' }
$binDir = Join-Path $RuntimeRoot 'bin'
$downloadDir = Join-Path $RuntimeRoot 'downloads'
$stagingRoot = Join-Path $RuntimeRoot 'staging'
New-Item -ItemType Directory -Force -Path $binDir, $downloadDir, $stagingRoot | Out-Null

$tools = @(
    @{ Name = 'ffuf'; Repo = 'ffuf/ffuf'; Pattern = 'windows_amd64\.zip$'; Executable = 'ffuf.exe' },
    @{ Name = 'subfinder'; Repo = 'projectdiscovery/subfinder'; Pattern = 'windows_amd64\.zip$'; Executable = 'subfinder.exe' },
    @{ Name = 'dalfox'; Repo = 'hahwul/dalfox'; Pattern = 'windows-x86_64\.zip$'; Executable = 'dalfox.exe' },
    @{ Name = 'gau'; Repo = 'lc/gau'; Pattern = 'windows_amd64\.zip$'; Executable = 'gau.exe' },
    @{ Name = 'amass'; Repo = 'owasp-amass/amass'; Pattern = 'windows_amd64\.tar\.gz$'; Executable = 'amass.exe' },
    @{ Name = 'trivy'; Repo = 'aquasecurity/trivy'; Pattern = 'windows-64bit\.zip$'; Executable = 'trivy.exe' }
)

function Get-ExpectedSha256 {
    param($Release, $Asset, [string]$DownloadDir)

    if ($Asset.digest -and $Asset.digest -match '^sha256:([0-9a-fA-F]{64})$') {
        return $Matches[1].ToLowerInvariant()
    }

    $checksumAsset = $Release.assets | Where-Object {
        $_.name -match '(?i)checksums?\.txt$|(?i)^checksum\.txt$'
    } | Select-Object -First 1
    if (-not $checksumAsset) {
        throw "No SHA-256 digest or checksum manifest is published for $($Asset.name)"
    }

    $checksumPath = Join-Path $DownloadDir $checksumAsset.name
    Invoke-WebRequest -Uri $checksumAsset.browser_download_url -Headers $headers -OutFile $checksumPath
    $escapedName = [regex]::Escape($Asset.name)
    $line = Get-Content -LiteralPath $checksumPath | Where-Object {
        $_ -match "^([0-9a-fA-F]{64})\s+\*?$escapedName$"
    } | Select-Object -First 1
    if (-not $line -or $line -notmatch '^([0-9a-fA-F]{64})') {
        throw "Checksum for $($Asset.name) is missing from $($checksumAsset.name)"
    }
    return $Matches[1].ToLowerInvariant()
}

$installed = foreach ($tool in $tools) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$($tool.Repo)/releases/latest" -Headers $headers
    $asset = $release.assets | Where-Object { $_.name -match $tool.Pattern } | Select-Object -First 1
    if (-not $asset) {
        throw "No Windows amd64 asset found for $($tool.Repo) using $($tool.Pattern)"
    }

    $archivePath = Join-Path $downloadDir $asset.name
    Invoke-WebRequest -Uri $asset.browser_download_url -Headers $headers -OutFile $archivePath
    $expected = Get-ExpectedSha256 -Release $release -Asset $asset -DownloadDir $downloadDir
    $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "SHA-256 mismatch for $($asset.name): expected $expected, got $actual"
    }

    $stageDir = Join-Path $stagingRoot ($tool.Name + '-' + $release.tag_name)
    $resolvedStagingRoot = [IO.Path]::GetFullPath($stagingRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedStageDir = [IO.Path]::GetFullPath($stageDir)
    if (-not $resolvedStageDir.StartsWith($resolvedStagingRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean staging path outside runtime root: $resolvedStageDir"
    }
    if (Test-Path -LiteralPath $stageDir) {
        Remove-Item -LiteralPath $stageDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
    if ($asset.name -match '(?i)\.zip$') {
        Expand-Archive -LiteralPath $archivePath -DestinationPath $stageDir -Force
    } elseif ($asset.name -match '(?i)\.tar\.gz$') {
        & tar.exe -xzf $archivePath -C $stageDir
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to extract $($asset.name)"
        }
    } else {
        throw "Unsupported archive format: $($asset.name)"
    }

    $executable = Get-ChildItem -LiteralPath $stageDir -Recurse -File -Filter $tool.Executable | Select-Object -First 1
    if (-not $executable) {
        throw "$($tool.Executable) not found in $($asset.name)"
    }
    $destination = Join-Path $binDir $tool.Executable
    Copy-Item -LiteralPath $executable.FullName -Destination $destination -Force
    [pscustomobject]@{
        Name = $tool.Name
        Version = $release.tag_name
        Executable = $destination
        Sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        ArchiveVerified = $true
    }
}

$installed | ConvertTo-Json -Depth 3
