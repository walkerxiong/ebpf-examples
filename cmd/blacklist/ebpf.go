package blacklist

import (
	"encoding/binary"
	"net"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
)

type XDPCollect struct {
	Prog         *ebpf.Program `ebpf:"firewall"`
	BlacklistMap *ebpf.Map     `ebpf:"blacklist_map"`
	MatchesMap   *ebpf.Map     `ebpf:"matches"`
}

func LoadXDPCollect(filename string) (*XDPCollect, error) {
	spec, err := ebpf.LoadCollectionSpec(filename)
	if err != nil {
		return nil, err
	}
	var obj = &XDPCollect{}
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		return nil, err
	}
	return obj, nil
}

func (x *XDPCollect) SetBlackIP(ipstr string, index uint32) error {
	if !strings.Contains(ipstr, "/") {
		ipstr += "/32"
	}
	_, ipnet, err := net.ParseCIDR(ipstr)
	if err != nil {
		return err
	}
	var res = make([]byte, x.BlacklistMap.KeySize())
	// key struct {uint32 , uint32}
	ones, _ := ipnet.Mask.Size()
	binary.LittleEndian.PutUint32(res, uint32(ones))
	copy(res[4:], ipnet.IP)
	if err := x.BlacklistMap.Put(res, index); err != nil {
		return err
	}
	matcheVal := make([]uint64, runtime.NumCPU())
	if err := x.MatchesMap.Put(index, matcheVal); err != nil {
		return err
	}
	return nil
}
