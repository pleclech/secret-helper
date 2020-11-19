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
	"os"
	"path/filepath"
	"time"

	"github.com/pleclech/secret-helper/path"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

var (
	keyName string
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a pair of private/public key",
	Long:  `Generate a pair of private/public key`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := generate(workingDir, keyName); err != nil {
			Fail(err)
		}
	},
}

func createFile(name string, private bool) (*os.File, error) {
	mode := os.FileMode(0644)
	if private {
		mode = 0600
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return nil, fmt.Errorf("Failed to create output file %q: %v", name, err)
	}
	return f, nil
}

func createFiles(workingDir, name string) (*os.File, *os.File, error) {
	if name == "-" {
		return os.Stdout, os.Stdout, nil
	}

	if filepath.IsAbs(name) {
		workingDir = filepath.Dir(name)
		name = filepath.Base(name)
	}

	privateName := filepath.Join(workingDir, fmt.Sprintf("%s.pri", name))
	if err := path.IsFile(privateName); err == nil {
		return nil, nil, fmt.Errorf("can't create file %q: file exist", privateName)
	}
	private, err := createFile(privateName, true)
	if err != nil {
		return nil, nil, err
	}

	publicName := filepath.Join(workingDir, fmt.Sprintf("%s.pub", name))
	if err := path.IsFile(publicName); err == nil {
		private.Close()
		return nil, nil, fmt.Errorf("can't create file %q: file exists", publicName)
	}
	public, err := createFile(publicName, false)
	if err != nil {
		private.Close()
		return nil, nil, err
	}

	return private, public, nil
}

func generate(workingDir, name string) error {
	private, public, err := createFiles(workingDir, name)
	if err != nil {
		return err
	}

	defer private.Close()
	defer public.Close()

	k, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}

	fmt.Fprintf(private, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(private, "# public key: %s\n", k.Recipient())
	fmt.Fprintf(private, "%s\n", k)

	fmt.Fprintf(public, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(public, "%s\n", k.Recipient())

	if public != os.Stdout {
		fmt.Fprintf(os.Stdout, "# public key: %s\n", k.Recipient())
	}

	return nil
}

func init() {
	cmd := keygenCmd
	flags := cmd.Flags()

	flags.StringVarP(&keyName, "name", "n", "", "file key name prefix")
	cmd.MarkFlagRequired("name")

	rootCmd.AddCommand(cmd)
}
