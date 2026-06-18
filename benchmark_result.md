```powershell
> powershell -ExecutionPolicy Bypass -File .\tests\benchmark-dnsrelay.ps1 -StartServer -Clients 20 -RequestsPerClient 50
DNS relay benchmark
Target      : 127.0.0.1:10530
Clients     : 20
Base port   : 20000
Local ports : 20000..20019
Per client   : 50
Domains     : 008.cn, 2qq.cn, 555.265.com, abc.265.com, abcdesign.ru, ad.qingyule.com, alexey.pioneers.com.ru, baltnet.ru, bupt, cctv1.net, cctv8.net, chinabdkx.363.net, ciachoo.pl, clients.babylon.co.il, dicto.ru, elemental.ru, errorguard.com, example.com, financial.washingtonpost.com, free.bestialityhost.com, friendlygreeting.com, sina, sohu, test1, test2, www.apple.com, www.baidu.com, www.bupt.edu.cn, www.cloudflare.com, www.github.com, www.microsoft.com, www.wikipedia.org
Requests    : 1000
Elapsed     : 3.500 s
Throughput  : 282.32 req/s
Success     : 988
Timeout     : 12
Errors      : 0
Latency ms  : avg=2.73 min=0.06 p50=0.38 p95=14.27 p99=23.35 max=56.39

Per-client summary:

ClientId LocalPort Requested Success Timeout Error
-------- --------- --------- ------- ------- -----
       0     20000        50      50       0     0
       1     20001        50      50       0     0
       2     20002        50      50       0     0
       3     20003        50      50       0     0
       4     20004        50      50       0     0
       5     20005        50      49       1     0
       6     20006        50      50       0     0
       7     20007        50      49       1     0
       8     20008        50      50       0     0
       9     20009        50      50       0     0
      10     20010        50      49       1     0
      11     20011        50      49       1     0
      12     20012        50      49       1     0
      13     20013        50      49       1     0
      14     20014        50      49       1     0
      15     20015        50      49       1     0
      16     20016        50      49       1     0
      17     20017        50      49       1     0
      18     20018        50      49       1     0
      19     20019        50      49       1     0
```