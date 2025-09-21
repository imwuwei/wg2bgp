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
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, pcap.BlockForever)
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
	}

	// 带时间戳的IP缓存
	var (
		ipCache   = make(map[string]time.Time)
		cacheLock sync.Mutex
	)

	// 打印并清理缓存
	printAndCleanCache := func() {
		cacheLock.Lock()
		defer cacheLock.Unlock()

		fmt.Println("\n=== IP地址缓存快照 ===")
		fmt.Println("时间:", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Println("有效IP地址（最近30秒内）:")

		// 清理过期IP并打印有效IP
		for ip, timestamp := range ipCache {
			if time.Since(timestamp) <= 30*time.Second {
				fmt.Printf("- %s (活跃于 %.0f秒前)\n", ip, time.Since(timestamp).Seconds())
			} else {
				delete(ipCache, ip)
			}
		}
		fmt.Println("=== \n")
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
		cacheLock.Lock()
		if _, exists := ipCache[srcIP]; exists {
			ipCache[srcIP] = time.Now()
			// fmt.Printf("更新IP时间戳: %s\n", srcIP)
		} else {
			ipCache[srcIP] = time.Now()
			// fmt.Printf("捕获新IP: %s\n", srcIP)
		}
		cacheLock.Unlock()
	}
}
