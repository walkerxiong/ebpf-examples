package route

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/walkerxiong/ebpf-examples/cmd/common"
)

var (
	kernObjFile string
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "route",
		Short: "Route the traffic",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			kernObjFile = args[0]
			run()
		},
	}
}

func run() {
	collect, err := LoadXDPCollect(kernObjFile)
	if err != nil {
		log.Fatalf("loading object : %v ", err)
	}
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
		log.Fatalf("route subscribe err %v", err)
	}

	go func() {
		for {
			select {
			case <-neighChan:
			case <-routeChan:
			}
			// delete the cached map
			var (
				entries = collect.CacheMap.Iterate()
				key     uint32
				value   rtItem
			)
			for entries.Next(&key, &value) {
				collect.CacheMap.Delete(key)
			}
			if err := entries.Err(); err != nil {
				log.Println("entries err ", err)
			}
			log.Println("arp map or router changed")
		}
	}()
	// load the network interface map
	var (
		ifaceList []netlink.Link
	)
	for _, value := range strings.Split(common.InNetIface, ",") {
		link, err := netlink.LinkByName(value)
		if err != nil {
			log.Println("network not found ", err)
			continue
		}
		ifaceList = append(ifaceList, link)
		ifindex := uint32(link.Attrs().Index)
		collect.IfDirectMap.Put(ifindex, ifindex)
		if err := netlink.LinkSetXdpFd(link, collect.Prog.FD()); err != nil {
			log.Fatalf("link set xdp err %v", err)
		}
	}

	var signals = make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	select {
	case <-signals:
	case <-closeChan:
	}
	for _, link := range ifaceList {
		netlink.LinkSetXdpFd(link, -1)
	}
	log.Println("ended")

}
