# DNS 中继服务器运行说明

本文档记录当前项目已经验证过的编译、运行和测试方式，环境为 Windows PowerShell + MinGW/GCC。

## 1. 编译

在项目根目录执行：

```powershell
New-Item -ItemType Directory -Force .\build
gcc .\src\dnsrelay.c -o .\build\dnsrelay.exe -lws2_32 -Wall -Wextra
```

生成的可执行文件为：

```text
.\build\dnsrelay.exe
```

## 2. 启动服务器

建议实验测试时使用非 53 端口，避免管理员权限和系统 DNS 服务占用问题：

```powershell
.\build\dnsrelay.exe -dd -p 10530 223.5.5.5 .\dnsrelay.txt
```

参数含义：

- `-dd`：输出详细调试信息。
- `-p 10530`：监听本地 UDP 10530 端口。
- `223.5.5.5`：上游 DNS 服务器。
- `.\dnsrelay.txt`：本地域名表，格式为 `IP 域名`。

启动成功时会看到类似输出：

```text
DNS relay started: listen=0.0.0.0:10530 upstream=223.5.5.5:53 table=.\dnsrelay.txt entries=208
```

## 3. 查询一个域名

另开一个 PowerShell 窗口，在项目根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\query-dnsrelay.ps1 -Domain www.baidu.com -Port 10530
```

如果 `www.baidu.com` 不在 `dnsrelay.txt` 中，程序会把请求中继到上游 DNS，并返回真实解析结果。

如果要测试本地自定义解析，可以在 `dnsrelay.txt` 里加入一行：

```text
1.2.3.4 www.baidu.com
```

然后重启服务器，再执行查询脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\query-dnsrelay.ps1 -Domain www.baidu.com -Port 10530
```

期望输出中包含：

```text
RCode: 0
A: 1.2.3.4
```

## 4. 不修改 dnsrelay.txt 的自动测试

可以直接运行完整测试脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\test-dnsrelay.ps1
```

这个脚本会自动完成以下操作：

- 临时生成测试用域名表，不修改项目里的 `dnsrelay.txt`。
- 启动 `build\dnsrelay.exe`。
- 验证自定义本地解析，例如 `www.baidu.com -> 1.2.3.4`。
- 验证 `0.0.0.0` 拦截会返回 NXDOMAIN。
- 验证未命中域名会转发到上游 DNS。
- 测试结束后自动停止服务器。

也可以指定自定义域名和期望 IP：

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\test-dnsrelay.ps1 -Domain www.baidu.com -ExpectedIp 1.2.3.4 -Port 10530
```

## 5. 关于 nslookup

Windows 自带的 `C:\Windows\System32\nslookup.exe` 在当前环境下测试非 53 端口不可靠。即使命令写成：

```powershell
nslookup -port=10530 www.baidu.com 127.0.0.1
```

也可能显示：

```text
No response from server
```

这不一定表示 DNS 中继服务器没有响应。当前项目已经用 `tests\query-dnsrelay.ps1` 直接发送 UDP DNS 报文验证过，服务器可以在 10530 端口正常返回结果。

如果必须使用 `nslookup`，更稳妥的方式是以管理员权限让程序监听默认 53 端口，并把系统 DNS 指向 `127.0.0.1` 后再测试。
