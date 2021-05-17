package blacklist

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/walkerxiong/ebpf-examples/cmd/common"
)

var (
	sourceIPs   []string
	kernObjFile string
)

func New() *cobra.Command {
	var blackCmd = &cobra.Command{
		Use:   "intercept",
		Short: "intercept the traffic from specific source ip ",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			kernObjFile = args[0]
			run()
		},
	}

	blackCmd.PersistentFlags().StringSliceVarP(&sourceIPs, "source", "sip", nil, "Source ip for intercept")
	return blackCmd
}

func run() {
	collect, err := LoadXDPCollect(kernObjFile)
	if err != nil {
		log.Fatalf("loading object : %v ", err)
	}

	// write blacklist to map
	for index, ip := range sourceIPs {
		collect.SetBlackIP(ip, uint32(index))
	}

	if err := common.AttachXDPProgram(collect.Prog.FD()); err != nil {
		log.Fatalf("attach err, %v", err)
	}
	log.Println("XDP program successfully loaded and attached.")
	log.Println("Press CTRL+C to stop.")

	var (
		stoper = make(chan os.Signal, 1)
		ticket = time.NewTicker(time.Second)
	)
	signal.Notify(stoper, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-stoper:
			log.Println("detaching network and exit")
			if err := common.DetachXDPProgram(); err != nil {
				log.Fatalf("detached network failed : %v", err)
			}
			return

		case <-ticket.C:
			for index, value := range sourceIPs {
				var counter []uint64
				if err := collect.MatchesMap.Lookup(uint32(index), &counter); err == nil {
					var sum uint64
					for _, n := range counter {
						sum += n
					}
					log.Printf("IP: %s DROP: %d \n", value, sum)
				}
			}
		}
	}
}
