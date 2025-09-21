### 介绍

用于将wg隧道中的客户端IP发布到BGP网络中。
客户端可以使用同一个IP在不同HUB节点中切换；
在网络中不需要使用NAT，服务端可以准确的识别出客户端IP。

### 依赖

FRR: 用于发布BGP路由

libpcap: 用于抓包，过滤出客户端IP。`apt install libpcap-dev`


### 使用方式

```bash
# 编译
go build -o wg2bgp

# 完整示例
./wg2bgp -d -i eth0 -f inbound -r 10.0.0.0/8 -a 64514 -s 64 -d

# 简单示例
./wg2bgp -d -i wg0 -r 10.0.0.0/8 -a 64514 -d

```
使用方法
```bash
Usage of wg2bgp:
  -a string
        ASN (default "64514")
  -d    Run as a daemon
  -f string
        BPF filter (default "inbound")
  -i string
        Network interface to capture packets from (default "eth0")
  -p    Promiscuous mode
  -r string
        IP range to filter (e.g., 192.168.1.0/24) (default "10.0.0.0/8")
  -s int
        Snapshot length (default 64)
```