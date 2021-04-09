package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	iface     string
	blacklist string
)

func init() {
	flag.StringVar(&iface, "iface", "ens33", "network interface to attach")
	flag.StringVar(&blacklist, "ip drops", "192.168.187.160/24", "ip blacklist, split by comma")
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang FirewallXDP ./ebpf/fw_xdp.c -- -I ./libbpf/src
func main() {
	flag.Parse()

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set terpory memory: %v", err)
	}

	objs := FirewallXDPObjects{}
	if err := LoadFirewallXDPObjects(&objs, nil); err != nil {
		log.Fatalf("loading object : %v ", err)
	}

	defer objs.Close()

	// write blacklist to map
	dropIP := strings.Split(blacklist, ",")
	for index, ip := range dropIP {
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			log.Printf("malformed ip %v \n", err)
			continue
		}
		var res = make([]byte, objs.BlacklistMap.KeySize())
		ones, _ := ipnet.Mask.Size()
		binary.LittleEndian.PutUint32(res, uint32(ones))
		copy(res[4:], ipnet.IP)
		if err := objs.BlacklistMap.Put(res, uint32(index)); err != nil {
			log.Fatalf("blacklist put err %v \n", err)
		}
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		log.Fatalf("%s network interface not found", iface)
	}
	if err := netlink.LinkSetXdpFd(link, objs.Firewall.FD()); err != nil {
		log.Fatalf("network attach error : %v", err)
	}

	log.Println("XDP program successfully loaded and attached.")
	log.Println("Press CTRL+C to stop.")

	var (
		stoper  = make(chan os.Signal, 1)
		ticket  = time.NewTicker(time.Second)
		entries = objs.BlacklistMap.Iterate()
		key     *net.IPNet
		value   uint32
	)
	signal.Notify(stoper, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-stoper:
			log.Println("detaching network and exit")
			if err := netlink.LinkSetXdpFd(link, -1); err != nil {
				log.Fatalf("detached network failed : %v", err)
			}
			return

		case <-ticket.C:
			for entries.Next(&key, &value) {
				log.Printf("IP: %18s \n", key)
				var counter uint64
				if err := objs.Matches.Lookup(&value, &counter); err == nil {
					log.Printf("IP: %18s DROP: %d \n", key, counter)
				}
			}
			if err := entries.Err(); err != nil {
				log.Fatalf("entries error %v", err)
			}
		}
	}
}
