package route

import (
	"github.com/cilium/ebpf"
)

type RouteCollect struct {
	Prog        *ebpf.Program `ebpf:"redirect"`
	IfDirectMap *ebpf.Map     `ebpf:"if_derect"`
	CacheMap    *ebpf.Map     `ebpf:"rtcache_map"`
}

type rtItem struct {
	Index int
	Smac  [6]byte
	Dmac  [6]byte
}

func LoadXDPCollect(filename string) (*RouteCollect, error) {
	spec, err := ebpf.LoadCollectionSpec(filename)
	if err != nil {
		return nil, err
	}
	var obj = &RouteCollect{}
	if err := spec.LoadAndAssign(obj, nil); err != nil {
		return nil, err
	}
	return obj, nil
}
