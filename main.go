package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/zh-five/xdaemon"
)

//	vtysh -c "configure terminal" \
//	    -c "router bgp 65001" \
//		-c "address-family ipv4 unicast" \
//		-c "network $ROUTE_PREFIX"
func addFrrRoute(ip string, asn string) error {
	// 构建vtysh命令
	cmd := fmt.Sprintf(`vtysh -c "configure terminal" \
			-c "router bgp %s" \
			-c "address-family ipv4 unicast" \
			-c "network %s/32"`, asn, ip)
	return executeCommand(cmd)
}

func delFrrRoute(ip string, asn string) error {
	// 构建vtysh命令
	cmd := fmt.Sprintf(`vtysh -c "configure terminal" \
			-c "router bgp %s" \
			-c "address-family ipv4 unicast" \
			-c "no network %s/32"`, asn, ip)
	return executeCommand(cmd)
}

func addRoute(ip string, iface *string) error {
	cmd := fmt.Sprintf("ip route replace %s dev %s", ip, *iface)
	return executeCommand(cmd)
}

func deleteRoute(ip string, iface *string) error {
	cmd := fmt.Sprintf("ip route delete %s dev %s", ip, *iface)
	return executeCommand(cmd)
}

func executeCommand(cmd string) error {
	// 执行系统命令并返回错误
	c := exec.Command("sh", "-c", cmd)
	if err := c.Run(); err != nil {
		return fmt.Errorf("执行命令失败: %v", err)
	}
	return nil
}

func cleanupRoutes(ipCache *sync.Map, iface *string, asn *string) {
	ipCache.Range(
		func(ip, _ interface{}) bool {
			if err := deleteRoute(ip.(string), iface); err != nil {
				log.Printf("删除路由失败: %v", err)
			}
			if err := delFrrRoute(ip.(string), *asn); err != nil {
				log.Printf("删除路由失败: %v", err)
			}
			return true
		})
}

func main() {
	// 带时间戳的IP缓存
	var ipCache sync.Map
	var ipCacheLock sync.Mutex // 保护ipCache的互斥锁
	// 定义命令行参数
	var (
		iface   = flag.String("i", "eth0", "Network interface to capture packets from")
		ipRange = flag.String("r", "10.0.0.0/8", "IP range to filter (e.g., 192.168.1.0/24)")
		snaplen = flag.Int("s", 64, "Snapshot length")
		promisc = flag.Bool("p", false, "Promiscuous mode")
		filter  = flag.String("f", "inbound", "BPF filter")
		asn     = flag.String("a", "64514", "ASN")
		daemon  = flag.Bool("d", false, "Run as a daemon")
	)
	flag.Parse()

	//启动守护进程
	if *daemon {
		//创建一个Daemon对象
		logFile := "/var/log/wg2bgp.log"
		daemon := xdaemon.NewDaemon(logFile)
		//调整一些运行参数(可选)
		daemon.MaxCount = 2 //最大重启次数
		//执行守护进程模式
		daemon.Run()
	}

	// 捕获退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cleanupRoutes(&ipCache, iface, asn)
		os.Exit(0)
	}()

	// 确保程序退出时清理路由
	defer cleanupRoutes(&ipCache, iface, asn)

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

	// 打印并清理缓存
	printAndCleanCache := func() {
		ipCacheLock.Lock()
		defer ipCacheLock.Unlock()

		// fmt.Println("\n=== IP地址缓存快照 ===")
		// fmt.Println("时间:", time.Now().Format("2006-01-02 15:04:05"))
		// fmt.Println("有效IP地址（最近30秒内）:")

		// 清理过期IP并打印有效IP
		ipCache.Range(
			func(ip, timestamp interface{}) bool {
				if t, ok := timestamp.(time.Time); ok {
					if time.Since(t) <= 30*time.Second {
						// fmt.Printf("- %s (活跃于 %.0f秒前)\n", ip, time.Since(t).Seconds())
						if err := addRoute(ip.(string), iface); err != nil {
							log.Printf("添加路由失败: %v", err)
						}
						if err := addFrrRoute(ip.(string), *asn); err != nil {
							log.Printf("添加bgp路由失败: %v", err)
						}
						return true
					} else {
						ipCache.Delete(ip)
						if err := deleteRoute(ip.(string), iface); err != nil {
							log.Printf("删除路由失败: %v", err)
						}
						if err := delFrrRoute(ip.(string), *asn); err != nil {
							log.Printf("删除路由失败: %v", err)
						}
						return true
					}
				}
				return true
			})
	}

	// 启动定时打印任务
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			printAndCleanCache()
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
