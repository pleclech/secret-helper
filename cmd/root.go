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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pleclech/secret-helper/cleanup"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	version    string
	workingDir string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "secret-helper",
	Short: "tool to encrypt secret",
	Long:  `tool to encrypt secret`,
}

// Fail exit printing error
func Fail(err error) {
	log.Error(err)
	cleanup.Exit(1)
}

func writeToFile(fileName string, content []byte, mode os.FileMode) error {
	tmpName := fileName + ".tmp"

	err := ioutil.WriteFile(tmpName, content, mode)
	if err != nil {
		return err
	}

	defer cleanup.Trap(func() { os.Remove(tmpName) })()

	return os.Rename(tmpName, fileName)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(v string) {
	version = v
	if err := rootCmd.Execute(); err != nil {
		Fail(err)
	}
}

func init() {
	cmd := rootCmd
	pflags := cmd.PersistentFlags()

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		Fail(err)
	}

	pflags.StringVarP(&workingDir, "cwd", "", dir, "change working dir")
}
