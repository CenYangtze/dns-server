param(
    [string]$Domain = "www.baidu.com",
    [string]$Server = "127.0.0.1",
    [int]$Port = 10530,
    [int]$TimeoutMs = 3000
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

function New-DnsAQuery {
    param([string]$Name)

    $bytes = [System.Collections.Generic.List[byte]]::new()
    $id = Get-Random -Minimum 1 -Maximum 65535
    Add-U16BE $bytes $id
    Add-U16BE $bytes 0x0100
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
    Add-U16BE $bytes 1
    Add-U16BE $bytes 1
    return $bytes.ToArray()
}

$packet = New-DnsAQuery $Domain
$client = [System.Net.Sockets.UdpClient]::new()
try {
    $client.Client.ReceiveTimeout = $TimeoutMs
    $client.Connect($Server, $Port)
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

$aRecords = @()
for ($i = 0; $i -lt $answerCount; $i++) {
    Skip-DnsName $response ([ref]$offset)
    if ($offset + 10 -gt $response.Length) {
        throw "DNS answer header truncated"
    }
    $type = Read-U16BE $response $offset
    $offset += 2
    $class = Read-U16BE $response $offset
    $offset += 2
    $offset += 4
    $rdlength = Read-U16BE $response $offset
    $offset += 2
    if ($offset + $rdlength -gt $response.Length) {
        throw "DNS answer RDATA truncated"
    }
    if ($type -eq 1 -and $class -eq 1 -and $rdlength -eq 4) {
        $ip = [System.Net.IPAddress]::new([byte[]]@($response[$offset], $response[$offset + 1], $response[$offset + 2], $response[$offset + 3]))
        $aRecords += $ip.ToString()
    }
    $offset += $rdlength
}

Write-Host "Server: ${Server}:$Port"
Write-Host "Domain: $Domain"
Write-Host "RCode: $rcode"
Write-Host "AnswerCount: $answerCount"
if ($aRecords.Count -gt 0) {
    Write-Host "A: $($aRecords -join ', ')"
} else {
    Write-Host "A: <none>"
}
