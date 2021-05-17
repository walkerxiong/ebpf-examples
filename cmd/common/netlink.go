package common

import (
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func AttachXDPProgram(fd int) error {
	link, err := netlink.LinkByName(InNetIface)
	if err != nil {
		return err
	}
	flag := nl.XDP_FLAGS_DRV_MODE & nl.XDP_FLAGS_UPDATE_IF_NOEXIST
	if err := netlink.LinkSetXdpFdWithFlags(link, fd, flag); err != nil {
		flag &= ^nl.XDP_FLAGS_DRV_MODE
		flag |= nl.XDP_FLAGS_SKB_MODE
		if err := netlink.LinkSetXdpFdWithFlags(link, fd, flag); err != nil {
			return err
		}
	}
	return nil
}

func DetachXDPProgram() error {
	link, err := netlink.LinkByName(InNetIface)
	if err != nil {
		return err
	}
	return netlink.LinkSetXdpFd(link, -1)
}
