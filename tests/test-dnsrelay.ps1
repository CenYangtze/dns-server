param(
    [string]$Domain = "www.baidu.com",
    [string]$ExpectedIp = "1.2.3.4",
    [int]$Port = 10530,
    [string]$Upstream = "223.5.5.5",
    [string]$Exe = ".\build\dnsrelay.exe",
    [switch]$SkipRelay
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

function Skip-DnsName {
    param(
        [byte[]]$Bytes,
        [ref]$Offset
    )
    while ($Offset.Value -lt $Bytes.Length) {
        $len = $Bytes[$Offset.Value]
        if (($len -band 0xc0) -eq 0xc0) {
            $Offset.Value += 2
            return
        }
        $Offset.Value++
        if ($len -eq 0) {
            return
        }
        $Offset.Value += $len
    }
    throw "Malformed DNS name"
}

function New-DnsQueryPacket {
    param([string]$Name)

    $bytes = [System.Collections.Generic.List[byte]]::new()
    $id = Get-Random -Minimum 1 -Maximum 65535
    Add-U16BE $bytes $id       # ID
    Add-U16BE $bytes 0x0100   # RD query
    Add-U16BE $bytes 1        # QDCOUNT
    Add-U16BE $bytes 0        # ANCOUNT
    Add-U16BE $bytes 0        # NSCOUNT
    Add-U16BE $bytes 0        # ARCOUNT

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
    Add-U16BE $bytes 1        # QTYPE A
    Add-U16BE $bytes 1        # QCLASS IN
    return $bytes.ToArray()
}

function Invoke-DnsAQuery {
    param(
        [string]$Name,
        [int]$ServerPort
    )

    $packet = New-DnsQueryPacket $Name
    $client = [System.Net.Sockets.UdpClient]::new()
    try {
        $client.Client.ReceiveTimeout = 3000
        $client.Connect("127.0.0.1", $ServerPort)
        [void]$client.Send($packet, $packet.Length)
        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $response = $client.Receive([ref]$remote)
    } finally {
        $client.Close()
    }

    if ($response.Length -lt 12) {
        throw "DNS response too short"
    }

    $flags = Read-U16BE $response 2
    $rcode = $flags -band 0x000f
    $answerCount = Read-U16BE $response 6
    $offset = 12
    Skip-DnsName $response ([ref]$offset)
    $offset += 4

    $answers = @()
    for ($i = 0; $i -lt $answerCount; $i++) {
        Skip-DnsName $response ([ref]$offset)
        if ($offset + 10 -gt $response.Length) {
            throw "DNS answer header truncated"
        }
        $type = Read-U16BE $response $offset
        $offset += 2
        $class = Read-U16BE $response $offset
        $offset += 2
        $ttl = (($response[$offset] -shl 24) -bor ($response[$offset + 1] -shl 16) -bor ($response[$offset + 2] -shl 8) -bor $response[$offset + 3])
        $offset += 4
        $rdlength = Read-U16BE $response $offset
        $offset += 2
        if ($offset + $rdlength -gt $response.Length) {
            throw "DNS answer RDATA truncated"
        }
        if ($type -eq 1 -and $class -eq 1 -and $rdlength -eq 4) {
            $ip = [System.Net.IPAddress]::new([byte[]]@($response[$offset], $response[$offset + 1], $response[$offset + 2], $response[$offset + 3]))
            $answers += $ip.ToString()
        }
        $offset += $rdlength
    }

    return [pscustomobject]@{
        Name = $Name
        RCode = $rcode
        AnswerCount = $answerCount
        ARecords = $answers
    }
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$exePath = if ([System.IO.Path]::IsPathRooted($Exe)) { $Exe } else { Join-Path $projectRoot $Exe }
$sourceTable = Join-Path $projectRoot "dnsrelay.txt"

if (-not (Test-Path -LiteralPath $exePath)) {
    throw "Executable not found: $exePath. Build it first with: gcc .\src\dnsrelay.c -o .\build\dnsrelay.exe -lws2_32"
}
if (-not (Test-Path -LiteralPath $sourceTable)) {
    throw "Table file not found: $sourceTable"
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dnsrelay-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$testTable = Join-Path $tempDir "dnsrelay-test.txt"
$stdout = Join-Path $tempDir "dnsrelay.out.log"
$stderr = Join-Path $tempDir "dnsrelay.err.log"

$blockedDomain = "blocked.local.test"
try {
    @(
        "$ExpectedIp $Domain"
        "0.0.0.0 $blockedDomain"
        (Get-Content -LiteralPath $sourceTable)
    ) | Set-Content -LiteralPath $testTable -Encoding ASCII

    $args = @("-dd", "-p", [string]$Port, $Upstream, $testTable)
    $proc = Start-Process -FilePath $exePath -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    Start-Sleep -Milliseconds 800

    if ($proc.HasExited) {
        $outText = if (Test-Path $stdout) { Get-Content -LiteralPath $stdout -Raw } else { "" }
        $errText = if (Test-Path $stderr) { Get-Content -LiteralPath $stderr -Raw } else { "" }
        throw "dnsrelay exited during startup. stdout: $outText stderr: $errText"
    }

    $local = Invoke-DnsAQuery -Name $Domain -ServerPort $Port
    if ($local.RCode -ne 0 -or $local.ARecords -notcontains $ExpectedIp) {
        throw "Local override failed for $Domain. RCode=$($local.RCode), A=$($local.ARecords -join ',')"
    }
    Write-Host "PASS local override: $Domain -> $($local.ARecords -join ', ')"

    $blocked = Invoke-DnsAQuery -Name $blockedDomain -ServerPort $Port
    if ($blocked.RCode -ne 3) {
        throw "Block/NXDOMAIN failed for $blockedDomain. RCode=$($blocked.RCode)"
    }
    Write-Host "PASS blocked domain: $blockedDomain -> NXDOMAIN"

    if (-not $SkipRelay) {
        $relay = Invoke-DnsAQuery -Name "example.com" -ServerPort $Port
        if ($relay.RCode -ne 0 -or $relay.ARecords.Count -eq 0) {
            throw "Relay query failed for example.com. RCode=$($relay.RCode), A=$($relay.ARecords -join ',')"
        }
        Write-Host "PASS relay query: example.com -> $($relay.ARecords -join ', ')"
    }

    Write-Host "Server log directory: $tempDir"
} finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
        $proc.WaitForExit()
    }
}
