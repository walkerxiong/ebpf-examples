package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type rtItem struct {
	Index int
	Smac  [6]byte
	Dmac  [6]byte
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang RedirectXDP ../../ebpf/redirect_xdp_kern.c -- -I ../../libbpf/src
func main() {
	var iface string
	flag.StringVar(&iface, "iface", "ens33", "network interface")
	flag.Parse()

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set terpory memory: %v \n", err)
	}

	var objs RedirectXDPObjects

	if err := LoadRedirectXDPObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load objects %v \n", err)
	}
	defer objs.Close()

	var (
		neighChan = make(chan netlink.NeighUpdate)
		routeChan = make(chan netlink.RouteUpdate)
		closeChan = make(chan struct{})
	)
	// listen for the arp map
	if err := netlink.NeighSubscribe(neighChan, closeChan); err != nil {
		log.Fatalf("arp map subscribe err %v ", err)
	}
	// listen for the route list
	if err := netlink.RouteSubscribe(routeChan, closeChan); err != nil {
		log.Fatal("route subscribe err %v", err)
	}

	go func() {
		for {
			select {
			case <-neighChan:
			case <-routeChan:
			}
			// delete the cached map
			var (
				entries = objs.RedirectXDPMaps.RtcacheMap.Iterate()
				key     uint32
				value   rtItem
			)
			for entries.Next(&key, &value) {
				objs.RedirectXDPMaps.RtcacheMap.Delete(key)
			}
			if err := entries.Err(); err != nil {
				log.Println("entries err ", err)
			}
			log.Println("arp map or router changed")
		}
	}()
	// load the network interface map
	for _, value := range strings.Split(iface, ",") {
		link, err := netlink.LinkByName(value)
		if err != nil {
			log.Println("network not found ", err)
			continue
		}
		ifindex := uint32(link.Attrs().Index)
		objs.RedirectXDPMaps.IfDerect.Put(ifindex, ifindex)
		if err := netlink.LinkSetXdpFd(link, objs.RedirectXDPPrograms.Redirect.FD()); err != nil {
			log.Fatalf("link set xdp err %v", err)
		}
	}

	var signals = make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	select {
	case <-signals:
	case <-closeChan:
	}
	log.Println("ended")

}
