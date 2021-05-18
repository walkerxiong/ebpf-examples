BUILDDIR=bin
EBPFDIR=ebpf
PROJECT="github.com/walkerxiong/ebpf-examples"
LDFLAGS = "-X $(PROJECT)/common.Version=$(Version)"
BLACKLISTOBJ="$(BUILDDIR)/xdp_blacklist.o"
ROUTEOBJ="$(BUILDDIR)/xdp_route.o"
FIREWALL=$(BUILDDIR)/firewall
LIBBPF_SRC=$(abspath ./libbpf/src)

.PHONY: all 
all: $(BLACKLISTOBJ) $(ROUTEOBJ) $(FIREWALL)

$(BLACKLISTOBJ):
	mkdir -p $(BUILDDIR)
	clang -I $(LIBBPF_SRC) -g -o $@ -c $(EBPFDIR)/blacklist.c

$(ROUTEOBJ):
	clang -I $(LIBBPF_SRC) -g -o $@ -c $(EBPFDIR)/route.c

$(FIREWALL):
	go build -ldflags $(LDFLAGS) -o $(FIREWALL) ./main.go

clean:
	rm -rf bin