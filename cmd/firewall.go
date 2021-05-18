package cmd

import (
	"github.com/spf13/cobra"
	"github.com/walkerxiong/ebpf-examples/cmd/blacklist"
	"github.com/walkerxiong/ebpf-examples/cmd/common"
	"github.com/walkerxiong/ebpf-examples/cmd/route"
)

var (
	rootCmd = &cobra.Command{
		Use:     "firewall",
		Short:   "A simple firewall application based on ebpf",
		Version: common.Version,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&common.InNetIface, "interface", "i", "", "Listen on network interface ")
	rootCmd.AddCommand(
		blacklist.New(),
		route.New(),
	)
}

func Execute() error {
	return rootCmd.Execute()
}
