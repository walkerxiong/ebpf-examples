BUILDDIR=bin
PROJECT="github.com/walkerxiong/ebpf-examples"
LDFLAGS = "-X $(PROJECT)/common.Version=$(Version)"
FIREWALL=$(BUILDDIR)/firewall

$(FIREWALL):
	go build -ldflags $(LDFLAGS) -o $(FIREWALL) ./main.go

clean:
	rm -rf bin