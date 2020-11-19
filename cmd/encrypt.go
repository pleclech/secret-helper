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
	"github.com/pleclech/secret-helper/crypt"
	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "decrypt a file or env or stdin",
	Long:  `decrypt a file or env or stdin`,
	Run: func(cmd *cobra.Command, args []string) {
		inf, err := crypt.NewInputInfo(workingDir, input, inputType, privateKey, publicKeys, vaultKey)
		if err != nil {
			Fail(err)
		}
		if err = inf.Validate(); err != nil {
			Fail(err)
		}

		if err = inf.Encrypt(); err != nil {
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

func init() {
	rootCmd.AddCommand(setupEdit(encryptCmd, "encrypt"))
}
