# DNS Relay Server

This project implements the DNS relay experiment described in `计算机网络实验二.pptx`.

## Features

- Reads an `IP domain` table from `dnsrelay.txt`.
- Returns a local A record when the queried domain is found with a normal IPv4 address.
- Returns NXDOMAIN when the queried domain is found with `0.0.0.0`.
- Relays unmatched queries to an upstream DNS server.
- Uses DNS ID translation so multiple clients can have outstanding relay queries at the same time.
- Cleans timed-out relay mappings.

## Build

Using MinGW/GCC on Windows:

```powershell
gcc .\src\dnsrelay.c -o .\build\dnsrelay.exe -lws2_32
```

Create the build directory first if it does not exist:

```powershell
New-Item -ItemType Directory -Force .\build
```

## Run

Syntax compatible with the experiment reference:

```text
dnsrelay [-d|-dd] [dns-server-ipaddr] [filename]
```

This implementation also supports `-p <port>` for local testing without binding to privileged port 53:

```powershell
.\build\dnsrelay.exe -dd -p 10530 8.8.8.8 .\dnsrelay.txt
```

For real DNS service on the local host, run as administrator and use the default port 53:

```powershell
.\build\dnsrelay.exe -d 8.8.8.8 .\dnsrelay.txt
```

## Example Tests

The repository includes PowerShell scripts for testing the server on a
non-privileged local port. This is the recommended method on Windows because
the built-in `nslookup.exe` may not reliably send queries to custom UDP ports.

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\test-dnsrelay.ps1
```

To query an already running server:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\query-dnsrelay.ps1 -Domain www.baidu.com -Port 10530
```

To test a custom local override without editing `dnsrelay.txt`:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\test-dnsrelay.ps1 -Domain www.baidu.com -ExpectedIp 1.2.3.4 -Port 10530
```

To run a simple multi-client concurrency benchmark:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\benchmark-dnsrelay.ps1 -StartServer -Clients 20 -RequestsPerClient 50
```

If you prefer Python, an equivalent benchmark is also available:

```powershell
python .\tests\benchmark-dnsrelay.py --start-server --clients 20 --requests-per-client 50
```

The benchmarks bind each client to a distinct local UDP port and mix
`dnsrelay.txt` entries with public domains by default. You can override the
local port base with `-BaseLocalPort` in PowerShell or `--base-local-port` in
Python, and you can supply your own domain list with `-Domains` / `--domains`.

The Python version uses the same idea and accepts `--base-local-port`,
`--table-sample-size`, and repeated `--public-domain` flags.

See `docs/RUNNING.md` for the full run and test guide.
