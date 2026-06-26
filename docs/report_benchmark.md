推荐运行 `python tests/benchmark-dnsrelay.py --start-server --servers [server-num] --clients [client-per-server-num] --output [output-file]` 命令以测试性能
可以通过 `--requests-per-client 40`, `--timeout-ms 3000`, `--exe ./build/dnsrelay_th.exe` 等参数实现更精细的操控（上述值均为默认值）

实验结果证明：
`dnsrelay_threaded.c` 和 `dnsrelay.c` 遵循大致相仿的规律，即测试规模在约 `10*2*20=400` 条请求以内时，吞吐量基本随测试规模和并行程度线性增加，可以轻易达到 `3000~6000 req/s`；当超过某一规模（最高不高于 `400` 的两倍）后，吞吐量迅速回归到 `200 req/s` 水平，但未见明显丢包，推测缓存正常，是上游服务器处理能力瓶颈。
在到达阈值之前的相同参数下，线程并行版本往往比原版的吞吐量更高。考虑到随机波动情况，应为线程并行版本的请求处理能力在一定程度上高于原版