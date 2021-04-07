package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	iface     string
	blacklist string
)

func init() {
	flag.StringVar(&iface, "iface", "ens33", "network interface to attach")
	flag.StringVar(&blacklist, "ip blacklist", "127.0.0.1", "ip blacklist, split by comma")
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang firewallXDP ./ebpf/fw_xdp.c -- -I ./libbpf/src
func main() {
	flag.Parse()
	stoper := make(chan os.Signal, 1)
	signal.Notify(stoper, os.Interrupt, syscall.SIGTERM)

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set terpory memory: %v", err)
	}

	objs := firewallXDPObjects{}
	if err := loadFirewallXDPObjects(objs, nil); err != nil {
		log.Fatalf("loading object : %v ", err)
	}
	defer objs.Close()

	blackl := strings.Split(blacklist, ",")
	for k := range blackl {
		objs.firewallXDPMaps.Blacklist.Put(unsafe.Pointer(&blackl[k]), uint32(k))
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

	<-stoper
	if err := netlink.LinkSetXdpFd(link, -1); err != nil {
		log.Fatalf("detached network failed : %v", err)
	}
}
