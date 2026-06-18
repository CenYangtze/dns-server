param(
    [string[]]$Domains = @(),
    [int]$Clients = 20,
    [int]$RequestsPerClient = 25,
    [string]$Server = "127.0.0.1",
    [int]$Port = 10530,
    [int]$TimeoutMs = 3000,
    [int]$BaseLocalPort = 20000,
    [int]$TableSampleSize = 24,
    [string[]]$PublicDomains = @(
        "example.com",
        "www.baidu.com",
        "www.bupt.edu.cn",
        "www.cloudflare.com",
        "www.microsoft.com",
        "www.github.com",
        "www.apple.com",
        "www.wikipedia.org"
    ),
    [switch]$StartServer,
    [string]$Exe = ".\build\dnsrelay.exe",
    [string]$Upstream = "8.8.8.8",
    [string]$TableFile = ".\dnsrelay.txt",
    [string]$StartupProbeDomain = "test1"
)

$ErrorActionPreference = "Stop"

function Add-U16BE {
    param(
        [System.Collections.Generic.List[byte]]$Bytes,
        [int]$Value
    )
    $Bytes.Add([byte](($Value -shr 8) -band 0xff))
    $Bytes.Add([byte]($Value -band 0xff))
}

function Read-U16BE {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )
    return (($Bytes[$Offset] -shl 8) -bor $Bytes[$Offset + 1])
}

function Normalize-DomainName {
    param([string]$Name)

    return $Name.Trim().TrimEnd(".").ToLowerInvariant()
}

function Read-BenchmarkDomainPool {
    param(
        [string]$Path,
        [string[]]$FallbackPublicDomains,
        [int]$RequestedTableSampleSize
    )

    $blocked = New-Object System.Collections.Generic.List[string]
    $local = New-Object System.Collections.Generic.List[string]
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if (Test-Path -LiteralPath $Path) {
        foreach ($line in Get-Content -LiteralPath $Path) {
            $trimmed = $line.Trim()
            if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) {
                continue
            }

            $parts = $trimmed -split '\s+', 3
            if ($parts.Count -lt 2) {
                continue
            }

            $ip = $parts[0]
            $domain = Normalize-DomainName $parts[1]
            if ($domain.Length -eq 0 -or -not $seen.Add($domain)) {
                continue
            }

            if ($ip -eq "0.0.0.0") {
                $blocked.Add($domain)
            } else {
                $parsedIp = $null
                if ([System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) {
                    $local.Add($domain)
                }
            }
        }
    }

    $targetTableCount = [Math]::Max(1, $RequestedTableSampleSize)
    $blockedTarget = [int][Math]::Min([Math]::Ceiling($targetTableCount / 2.0), $blocked.Count)
    $localTarget = [int][Math]::Min($targetTableCount - $blockedTarget, $local.Count)

    if (($blockedTarget + $localTarget) -lt $targetTableCount) {
        $remaining = [int]($targetTableCount - ($blockedTarget + $localTarget))
        $blockedExtra = [int][Math]::Min($remaining, $blocked.Count - $blockedTarget)
        $blockedTarget += $blockedExtra
        $remaining -= $blockedExtra
        if ($remaining -gt 0) {
            $localTarget += [int][Math]::Min($remaining, $local.Count - $localTarget)
        }
    }

    $pool = New-Object System.Collections.Generic.List[string]
    foreach ($domain in ($blocked | Select-Object -First $blockedTarget)) {
        $pool.Add($domain)
    }
    foreach ($domain in ($local | Select-Object -First $localTarget)) {
        $pool.Add($domain)
    }

    foreach ($domain in $FallbackPublicDomains) {
        $normalized = Normalize-DomainName $domain
        if ($normalized.Length -gt 0) {
            $pool.Add($normalized)
        }
    }

    return @($pool | Sort-Object -Unique)
}

function New-DnsQueryPacket {
    param(
        [string]$Name,
        [int]$Id
    )

    $bytes = [System.Collections.Generic.List[byte]]::new()

    # DNS 头部 12 字节：
    # ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    Add-U16BE $bytes $Id
    Add-U16BE $bytes 0x0100   # RD=1，表示希望递归查询
    Add-U16BE $bytes 1
    Add-U16BE $bytes 0
    Add-U16BE $bytes 0
    Add-U16BE $bytes 0

    foreach ($label in $Name.TrimEnd(".").Split(".")) {
        $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
        if ($labelBytes.Length -gt 63) {
            throw "DNS label too long: $label"
        }
        $bytes.Add([byte]$labelBytes.Length)
        foreach ($b in $labelBytes) {
            $bytes.Add($b)
        }
    }

    $bytes.Add(0)
    Add-U16BE $bytes 1   # QTYPE = A
    Add-U16BE $bytes 1   # QCLASS = IN
    return $bytes.ToArray()
}

function Get-DnsRCode {
    param([byte[]]$Response)

    if ($Response.Length -lt 4) {
        throw "DNS response too short"
    }

    $flags = Read-U16BE $Response 2
    return ($flags -band 0x000f)
}

function Get-Percentile {
    param(
        [double[]]$Values,
        [double]$Percentile
    )

    if (-not $Values -or $Values.Count -eq 0) {
        return $null
    }

    $sorted = $Values | Sort-Object
    $rank = [math]::Ceiling(($Percentile / 100.0) * $sorted.Count)
    if ($rank -lt 1) {
        $rank = 1
    }
    if ($rank -gt $sorted.Count) {
        $rank = $sorted.Count
    }
    return [double]$sorted[$rank - 1]
}

function Wait-DnsRelayReady {
    param(
        [string]$TargetServer,
        [int]$TargetPort,
        [string]$ProbeDomain,
        [int]$TimeoutMs
    )

    for ($i = 0; $i -lt 30; $i++) {
        try {
            $client = [System.Net.Sockets.UdpClient]::new()
            try {
                $client.Client.ReceiveTimeout = $TimeoutMs
                $client.Connect($TargetServer, $TargetPort)
                $packet = New-DnsQueryPacket -Name $ProbeDomain -Id 12345
                [void]$client.Send($packet, $packet.Length)
                $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                [void]$client.Receive([ref]$remote)
                return $true
            } finally {
                $client.Close()
            }
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }

    return $false
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$exePath = if ([System.IO.Path]::IsPathRooted($Exe)) { $Exe } else { Join-Path $projectRoot $Exe }
$tablePath = if ([System.IO.Path]::IsPathRooted($TableFile)) { $TableFile } else { Join-Path $projectRoot $TableFile }

if ($StartServer) {
    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "Executable not found: $exePath. Build it first with: gcc .\src\dnsrelay.c -o .\build\dnsrelay.exe -lws2_32"
    }
    if (-not (Test-Path -LiteralPath $tablePath)) {
        throw "Table file not found: $tablePath"
    }
}

if ($BaseLocalPort -lt 1024 -or $BaseLocalPort -gt 65535) {
    throw "BaseLocalPort must be in the range 1024..65535"
}
if (($BaseLocalPort + $Clients - 1) -gt 65535) {
    throw "BaseLocalPort + Clients exceeds the UDP port range"
}

$domainPool = if ($Domains.Count -gt 0) {
    @($Domains | ForEach-Object { Normalize-DomainName $_ } | Where-Object { $_.Length -gt 0 } | Select-Object -Unique)
} else {
    Read-BenchmarkDomainPool -Path $tablePath -FallbackPublicDomains $PublicDomains -RequestedTableSampleSize $TableSampleSize
}

if ($domainPool.Count -lt 1) {
    throw "No benchmark domains available."
}

$proc = $null
$tempDir = $null
$stdout = $null
$stderr = $null

try {
    if ($StartServer) {
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dnsrelay-bench-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
        $stdout = Join-Path $tempDir "dnsrelay.out.log"
        $stderr = Join-Path $tempDir "dnsrelay.err.log"

        $args = @("-dd", "-p", [string]$Port, $Upstream, $tablePath)
        $proc = Start-Process -FilePath $exePath -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr

        if (-not (Wait-DnsRelayReady -TargetServer "127.0.0.1" -TargetPort $Port -ProbeDomain $StartupProbeDomain -TimeoutMs $TimeoutMs)) {
            $outText = if (Test-Path $stdout) { Get-Content -LiteralPath $stdout -Raw } else { "" }
            $errText = if (Test-Path $stderr) { Get-Content -LiteralPath $stderr -Raw } else { "" }
            throw "dnsrelay did not become ready. stdout: $outText stderr: $errText"
        }

        $Server = "127.0.0.1"
    }

    $domainsCopy = @($domainPool)
    $workerScript = {
        param(
            [int]$ClientId,
            [int]$LocalPort,
            [string]$TargetServer,
            [int]$TargetPort,
            [string[]]$TargetDomains,
            [int]$TotalRequests,
            [int]$ReceiveTimeoutMs
        )

        function Add-U16BE {
            param(
                [System.Collections.Generic.List[byte]]$Bytes,
                [int]$Value
            )
            $Bytes.Add([byte](($Value -shr 8) -band 0xff))
            $Bytes.Add([byte]($Value -band 0xff))
        }

        function Read-U16BE {
            param(
                [byte[]]$Bytes,
                [int]$Offset
            )
            return (($Bytes[$Offset] -shl 8) -bor $Bytes[$Offset + 1])
        }

        function New-DnsQueryPacket {
            param(
                [string]$Name,
                [int]$Id
            )

            $bytes = [System.Collections.Generic.List[byte]]::new()
            Add-U16BE $bytes $Id
            Add-U16BE $bytes 0x0100
            Add-U16BE $bytes 1
            Add-U16BE $bytes 0
            Add-U16BE $bytes 0
            Add-U16BE $bytes 0

            foreach ($label in $Name.TrimEnd(".").Split(".")) {
                $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
                $bytes.Add([byte]$labelBytes.Length)
                foreach ($b in $labelBytes) {
                    $bytes.Add($b)
                }
            }

            $bytes.Add(0)
            Add-U16BE $bytes 1
            Add-U16BE $bytes 1
            return $bytes.ToArray()
        }

        function Get-DnsRCode {
            param([byte[]]$Response)
            $flags = Read-U16BE $Response 2
            return ($flags -band 0x000f)
        }

        $localEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $LocalPort)
        $client = [System.Net.Sockets.UdpClient]::new($localEndpoint)
        $latencies = New-Object System.Collections.Generic.List[double]
        $successCount = 0
        $timeoutCount = 0
        $errorCount = 0
        $rng = [System.Random]::new((Get-Random -Minimum 1 -Maximum 2147483647))

        try {
            $client.Client.ReceiveTimeout = $ReceiveTimeoutMs
            $client.Connect($TargetServer, $TargetPort)

            for ($i = 0; $i -lt $TotalRequests; $i++) {
                $domain = $TargetDomains[$rng.Next(0, $TargetDomains.Count)]
                $packet = New-DnsQueryPacket -Name $domain -Id $rng.Next(1, 65535)

                try {
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    [void]$client.Send($packet, $packet.Length)
                    $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                    $response = $client.Receive([ref]$remote)
                    $stopwatch.Stop()

                    $rcode = Get-DnsRCode -Response $response
                    if ($rcode -in 0, 3) {
                        $successCount++
                        $latencies.Add($stopwatch.Elapsed.TotalMilliseconds)
                    } else {
                        $errorCount++
                    }
                } catch {
                    $inner = $_.Exception
                    while ($inner.InnerException) {
                        $inner = $inner.InnerException
                    }

                    if ($inner -is [System.Net.Sockets.SocketException] -and $inner.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                        $timeoutCount++
                    } else {
                        $errorCount++
                    }
                }
            }
        } finally {
            $client.Close()
        }

        [pscustomobject]@{
            ClientId  = $ClientId
            LocalPort = $LocalPort
            Requested = $TotalRequests
            Success   = $successCount
            Timeout   = $timeoutCount
            Error     = $errorCount
            Latencies = $latencies.ToArray()
        }
    }

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [Math]::Max(1, $Clients))
    $pool.Open()
    $jobs = New-Object System.Collections.Generic.List[object]

    $overallTimer = [System.Diagnostics.Stopwatch]::StartNew()
    for ($clientId = 0; $clientId -lt $Clients; $clientId++) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $localPort = $BaseLocalPort + $clientId
        [void]$ps.AddScript($workerScript).AddArgument($clientId).AddArgument($localPort).AddArgument($Server).AddArgument($Port).AddArgument($domainsCopy).AddArgument($RequestsPerClient).AddArgument($TimeoutMs)
        $handle = $ps.BeginInvoke()
        $jobs.Add([pscustomobject]@{
            PowerShell = $ps
            Handle = $handle
        })
    }

    $summaries = New-Object System.Collections.Generic.List[object]
    foreach ($job in $jobs) {
        $result = $job.PowerShell.EndInvoke($job.Handle)
        $job.PowerShell.Dispose()
        if ($result -and $result.Count -gt 0) {
            $summaries.Add($result[0])
        }
    }
    $overallTimer.Stop()
    $pool.Close()
    $pool.Dispose()

    $allLatencies = New-Object System.Collections.Generic.List[double]
    $totalRequested = 0
    $totalSuccess = 0
    $totalTimeout = 0
    $totalError = 0

    foreach ($summary in $summaries) {
        $totalRequested += [int]$summary.Requested
        $totalSuccess += [int]$summary.Success
        $totalTimeout += [int]$summary.Timeout
        $totalError += [int]$summary.Error
        foreach ($lat in $summary.Latencies) {
            $allLatencies.Add([double]$lat)
        }
    }

    $elapsedSeconds = [Math]::Max(0.001, $overallTimer.Elapsed.TotalSeconds)
    $throughput = $totalSuccess / $elapsedSeconds
    $latencyValues = $allLatencies.ToArray()
    $avgLatency = if ($latencyValues.Count -gt 0) { ($latencyValues | Measure-Object -Average).Average } else { $null }
    $minLatency = if ($latencyValues.Count -gt 0) { ($latencyValues | Measure-Object -Minimum).Minimum } else { $null }
    $maxLatency = if ($latencyValues.Count -gt 0) { ($latencyValues | Measure-Object -Maximum).Maximum } else { $null }
    $p50 = Get-Percentile -Values $latencyValues -Percentile 50
    $p95 = Get-Percentile -Values $latencyValues -Percentile 95
    $p99 = Get-Percentile -Values $latencyValues -Percentile 99

    Write-Host "DNS relay benchmark"
    Write-Host "Target      : ${Server}:$Port"
    Write-Host "Clients     : $Clients"
    Write-Host "Base port   : $BaseLocalPort"
    Write-Host ("Local ports : {0}..{1}" -f $BaseLocalPort, ($BaseLocalPort + $Clients - 1))
    Write-Host "Per client   : $RequestsPerClient"
    Write-Host "Domains     : $($domainPool -join ', ')"
    Write-Host "Requests    : $totalRequested"
    Write-Host ("Elapsed     : {0:N3} s" -f $elapsedSeconds)
    Write-Host ("Throughput  : {0:N2} req/s" -f $throughput)
    Write-Host "Success     : $totalSuccess"
    Write-Host "Timeout     : $totalTimeout"
    Write-Host "Errors      : $totalError"
    if ($avgLatency -ne $null) {
        Write-Host ("Latency ms  : avg={0:N2} min={1:N2} p50={2:N2} p95={3:N2} p99={4:N2} max={5:N2}" -f $avgLatency, $minLatency, $p50, $p95, $p99, $maxLatency)
    } else {
        Write-Host "Latency ms  : <no successful responses>"
    }

    if ($totalError -gt 0 -or $totalTimeout -gt 0) {
        Write-Host ""
        Write-Host "Per-client summary:"
        $summaries |
            Sort-Object ClientId |
            Select-Object ClientId, LocalPort, Requested, Success, Timeout, Error |
            Format-Table -AutoSize
    }
} finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
        $proc.WaitForExit()
    }
}
