package cmd

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/proofpoint/kubernetes-ldap/token"
	"github.com/spf13/cobra"
	"os"
)

// genKeypairCmd represents the genKeypair command
var genKeypairCmd = &cobra.Command{
	Use:   "gen-keypair",
	Short: "generate a new keypair for signing/verifying the token",
	Run: func(cmd *cobra.Command, args []string) {
		if _, err := os.Stat(keypairDir); os.IsNotExist(err) {
			os.MkdirAll(keypairDir, 0700)
		}

		if err := token.GenerateKeypair(keypairDir); err != nil {
			glog.Errorf("Error generating key pair: %v", err)
			os.Exit(1)
		}
		fmt.Printf("Generated keypair in %s\n", keypairDir)
	},
}

func init() {
	RootCmd.AddCommand(genKeypairCmd)
}
