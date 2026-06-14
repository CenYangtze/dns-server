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

In another terminal, query a local table entry:

```powershell
nslookup -port=10530 test1 127.0.0.1
```

Expected result: `11.111.11.111`.

Query a blocked entry:

```powershell
nslookup -port=10530 test0 127.0.0.1
```

Expected result: NXDOMAIN.

Query an unmatched public domain:

```powershell
nslookup -port=10530 www.bupt.edu.cn 127.0.0.1
```

Expected result: the server relays the query to the configured upstream DNS server.
