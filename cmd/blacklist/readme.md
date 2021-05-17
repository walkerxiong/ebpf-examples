# 步骤

```
[root@localhost firewall]# go generate
Compiled /mnt/hgfs/workspace/study/ebpf-examples/cmd/firewall/firewallxdp_bpfel.o
Wrote /mnt/hgfs/workspace/study/ebpf-examples/cmd/firewall/firewallxdp_bpfel.go
Compiled /mnt/hgfs/workspace/study/ebpf-examples/cmd/firewall/firewallxdp_bpfeb.o
Wrote /mnt/hgfs/workspace/study/ebpf-examples/cmd/firewall/firewallxdp_bpfeb.go

[root@localhost firewall]# go build -o firewalld

[root@localhost firewall]# ./firewalld -iface ens33 -drop 192.168.187.161/32
2021/04/26 22:45:04 XDP program successfully loaded and attached.
2021/04/26 22:45:04 Press CTRL+C to stop.
2021/04/26 22:45:05 IP: 192.168.187.161/32 DROP: 0 
2021/04/26 22:45:06 IP: 192.168.187.161/32 DROP: 0 
2021/04/26 22:45:07 IP: 192.168.187.161/32 DROP: 0 
2021/04/26 22:45:08 IP: 192.168.187.161/32 DROP: 1 
2021/04/26 22:45:09 IP: 192.168.187.161/32 DROP: 2 
2021/04/26 22:45:10 IP: 192.168.187.161/32 DROP: 3 
2021/04/26 22:45:11 IP: 192.168.187.161/32 DROP: 3 
```