package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// 定义命令行参数
	var (
		iface   = flag.String("i", "eth0", "Network interface to capture packets from")
		ipRange = flag.String("r", "", "IP range to filter (e.g., 192.168.1.0/24)")
		snaplen = flag.Int("s", 65536, "Snapshot length")
		promisc = flag.Bool("p", false, "Promiscuous mode")
		filter  = flag.String("f", "", "BPF filter")
	)
	flag.Parse()

	// 打开网卡
	var handle *pcap.Handle
	var err error
	for i := 0; i < 3; i++ {
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), *promisc, pcap.BlockForever)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		fmt.Println("错误：无法打开网卡，请确保已安装 libpcap-dev。")
		fmt.Println("安装命令：sudo apt-get update && sudo apt-get install -y libpcap-dev")
		log.Fatal(err)
	}
	defer handle.Close()

	// 设置BPF过滤器
	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Fatal(err)
		}
	}

	// 解析IP范围
	var ipNet *net.IPNet
	if *ipRange != "" {
		_, ipNet, err = net.ParseCIDR(*ipRange)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println("警告：未指定IP范围，将捕获所有流量")
	}

	// 带时间戳的IP缓存
	var ipCache sync.Map
	var ipCacheLock sync.Mutex // 保护ipCache的互斥锁

	// 打印并清理缓存
	printAndCleanCache := func() {
		ipCacheLock.Lock()
		defer ipCacheLock.Unlock()

		fmt.Println("\n=== IP地址缓存快照 ===")
		fmt.Println("时间:", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Println("有效IP地址（最近30秒内）:")

		// 清理过期IP并打印有效IP
		ipCache.Range(
			func(ip, timestamp interface{}) bool {
				if t, ok := timestamp.(time.Time); ok {
					if time.Since(t) <= 30*time.Second {
						fmt.Printf("- %s (活跃于 %.0f秒前)\n", ip, time.Since(t).Seconds())
						return true
					} else {
						ipCache.Delete(ip)
						return true
					}
				}
				return true
			})
		// fmt.Println("===\n")
	}

	// 启动定时打印任务
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				printAndCleanCache()
			}
		}
	}()

	// 开始抓包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 提取网络层信息
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		// 获取源IP
		srcIP := networkLayer.NetworkFlow().Src().String()

		// 过滤IP范围
		if ipNet != nil && !ipNet.Contains(net.ParseIP(srcIP)) {
			continue
		}

		// 捕获新IP时检查并更新缓存
		ipCache.Store(srcIP, time.Now())
	}
}
