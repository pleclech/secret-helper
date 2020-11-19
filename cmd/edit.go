/*
Copyright © 2020 pleclech

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/pleclech/secret-helper/crypt"
	"github.com/spf13/cobra"
)

var (
	input      string
	output     string
	inputType  string
	privateKey string
	publicKeys []string
	vaultKey   string
)

// editCmd represents the edit command
var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "decrypt, edit and then save encrypted",
	Long:  `decrypt, edit and then save encrypted`,
	Run: func(cmd *cobra.Command, args []string) {
		inf, err := crypt.NewInputInfo(workingDir, input, inputType, privateKey, publicKeys, vaultKey)
		if err != nil {
			Fail(err)
		}
		if err = inf.Validate(); err != nil {
			Fail(err)
		}

		if err = inf.Edit(); err != nil {
			Fail(err)
		}

		if output == "" && inf.ContentName() != "" {
			output = inf.ContentName()
		}

		if err = inf.Save(output); err != nil {
			Fail(err)
		}
	},
}

func setupEdit(cmd *cobra.Command, mode string) *cobra.Command {
	flags := cmd.Flags()

	flags.StringVarP(&input, "input", "i", "", fmt.Sprintf("input file to %s or - for stdin", mode))
	cmd.MarkFlagRequired("input")

	flags.StringVarP(&inputType, "type", "t", "", fmt.Sprintf("type of file to %s (yaml)", mode))

	flags.StringVarP(&privateKey, "age-private-key", "", "", "private key use to decrypt, can be prefix by file://, env://, or nothing")

	flags.StringVarP(&vaultKey, "vault-key", "", "", "symetric key use to encrypt/decrypt !vault tag, can be prefix by file://, env://, or nothing")

	flags.StringSliceVarP(&publicKeys, "age-public-key", "", nil, "public key use to encrypt, can be prefix by file://, env://, or nothing. (can be repeated to allow multiple recipients)")

	flags.StringVarP(&output, "output", "o", "", "output file to save or - for stdout")

	return cmd
}

func init() {
	rootCmd.AddCommand(setupEdit(editCmd, "edit"))
}
